# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Characterization goldens for suppression predicate matching.

This module pins what the predicate-evaluation core does TODAY: the
``AshSuppression.matches`` family and ``scope_value_matches`` in
``models/core.py`` and the predicate functions of
``utils/suppression_matcher.py`` (``matches_suppression``, ``_rule_id_matches``,
``file_path_matches``, ``ignore_path_matches``, ``_line_range_matches``,
``should_suppress_finding``, ``accepting_unconverted_input``,
``active_ignore_paths``).

A wrong match here either silences a real finding or un-silences a suppressed
one, so the cases below are not a statement of what the matcher should do. They
record what it does, quirks included (a bracketed package glob that does not
match its own literal text, a rule-id helper that disagrees with the method for
bracketed ids, ``*`` that crosses ``/``). A case that goes red is a change in
behavior to be explained, never a golden to be refreshed.

Two kinds of pin:

* hand-written tables of single cases, each with the reason it reads that way;
* an exhaustive generated corpus (``itertools.product`` over small value
  spaces, no randomness) whose full outcome string is pinned by its SHA-256 and
  its count of matches. ``corpus_outcomes`` takes the match function as an
  argument, so a replacement implementation is run through the same corpus and
  must produce the same digest.
"""

import hashlib
import itertools
from datetime import date

import pytest

from automated_security_helper.models import core as core_module
from automated_security_helper.models.core import (
    AshSuppression,
    IgnorePathWithReason,
    scope_value_matches,
)
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.utils import suppression_scope_registry as registry
from automated_security_helper.utils.path_matching import _path_pattern_matches
from automated_security_helper.utils.suppression_matcher import (
    UNCONVERTED_INPUT_RULE,
    _line_range_matches as module_line_range_matches,
    _rule_id_matches,
    accepting_unconverted_input,
    active_ignore_paths,
    file_path_matches,
    ignore_path_matches,
    matches_suppression,
    should_suppress_finding,
)
from automated_security_helper.utils.unknown_keys import TOLERATE_STORED_CONFIG

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# builders
# ---------------------------------------------------------------------------


def finding(**overrides) -> FlatVulnerability:
    values = {
        "id": "f1",
        "title": "t",
        "description": "d",
        "severity": "HIGH",
        "scanner": "bandit",
        "scanner_type": "SAST",
        "rule_id": "B602",
        "file_path": "src/app.py",
        "line_start": 10,
        "line_end": 12,
    }
    values.update(overrides)
    return FlatVulnerability(**values)


def supp(**overrides) -> AshSuppression:
    values = {"path": "**", "reason": "r"}
    values.update(overrides)
    return AshSuppression.model_validate(values)


def stored(**overrides) -> AshSuppression:
    """An entry as a results file keeps it (the tolerance a stored config gets)."""
    values = {"path": "**", "reason": "r"}
    values.update(overrides)
    return AshSuppression.model_validate(values, context={TOLERATE_STORED_CONFIG: []})


class RecordingResolver:
    """A symbol resolver double: records each ``contains`` call, answers a fixed bool."""

    def __init__(self, answer: bool) -> None:
        self.answer = answer
        self.calls: list[tuple] = []

    def contains(self, file_path, line_start, line_end, symbol) -> bool:
        self.calls.append((file_path, line_start, line_end, symbol))
        return self.answer


class FakeEngineHooks:
    """The hook surface a registered scanner plugin class exposes."""

    @classmethod
    def validate_suppression_scope(cls, block):
        return []

    @classmethod
    def suppression_scope_matches(cls, block, finding):
        return block.get("marker") == finding.rule_id

    @classmethod
    def split_rule_qualifier(cls, rule_id):
        open_at = rule_id.find("[")
        if open_at == -1 or not rule_id.endswith("]"):
            return rule_id, None
        return rule_id[:open_at], rule_id[open_at + 1 : -1] or None


@pytest.fixture
def fake_engine(monkeypatch):
    monkeypatch.setitem(registry._ENGINE_HOOKS, "fake-engine", FakeEngineHooks)
    return "fake-engine"


@pytest.fixture(autouse=True)
def _clean_warn_state():
    registry.reset_unmatched_engine_warnings()
    yield
    registry.reset_unmatched_engine_warnings()


@pytest.fixture
def today(monkeypatch):
    """Pin the host date every expiration is read against."""

    def pin(year, month, day):
        monkeypatch.setattr(core_module, "current_date", lambda: date(year, month, day))

    return pin


# ---------------------------------------------------------------------------
# rule_id
# ---------------------------------------------------------------------------


class TestRuleId:
    @pytest.mark.parametrize(
        "sup_rule,find_rule,expected",
        [
            # no rule_id on the entry: any rule, a missing one included
            (None, "B602", True),
            (None, None, True),
            # a rule_id on the entry never matches a finding with no rule
            ("B602", None, False),
            # exact, any case
            ("B602", "B602", True),
            ("B602", "b602", True),
            ("b602", "B602", True),
            ("B602", "B603", False),
            # globs: * ? [set], on the lowercased pair
            ("B6*", "B602", True),
            ("b6*", "B602", True),
            ("B?02", "B602", True),
            ("B??", "B602", False),
            ("[BC]602", "B602", True),
            ("[!B]602", "B602", False),
            ("*", "anything", True),
            ("*602", "B602", True),
            # * crosses every character, including separators
            ("a*c", "a/b/c", True),
            # an unclosed [ is a literal character
            ("B[", "B[", True),
            ("B[", "Bx", False),
            # a bracketed id matches itself exactly, not as a class
            (
                "AwsSolutions-IAM5[Action::logs:*]",
                "AwsSolutions-IAM5[Action::logs:*]",
                True,
            ),
            # ...and its own text read as a glob still matches the same finding
            # only through the exact comparison, never a sibling
            (
                "AwsSolutions-IAM5[Action::logs:*]",
                "AwsSolutions-IAM5[Action::logs:Put]",
                False,
            ),
            # no scope: the base id of a qualified finding is not consulted
            ("AwsSolutions-IAM5", "AwsSolutions-IAM5[Resource::*]", False),
            # unicode: lower() only, no casefold
            ("ÄB", "äb", True),
            ("straße", "STRASSE", False),
        ],
    )
    def test_unscoped_entry(self, sup_rule, find_rule, expected):
        assert supp(rule_id=sup_rule).matches(finding(rule_id=find_rule)) is expected

    @pytest.mark.parametrize("blank", ["", " ", "\t", "  \n"])
    def test_a_blank_rule_id_kept_from_a_results_file_matches_nothing(self, blank):
        entry = stored(rule_id=blank)
        assert entry.matches(finding(rule_id="B602")) is False
        assert entry.matches(finding(rule_id=None)) is False

    def test_scoped_entry_also_matches_the_engine_base_id(self, fake_engine):
        entry = supp(
            rule_id="AwsSolutions-IAM5", scope={"resource_type": "AWS::IAM::Policy"}
        )
        qualified = finding(
            scanner=fake_engine,
            rule_id="AwsSolutions-IAM5[Resource::*]",
            resource_type="AWS::IAM::Policy",
        )
        assert entry.matches(qualified) is True
        # the base compares case-insensitively and as a glob
        upper = supp(
            rule_id="AWSSOLUTIONS-iam5", scope={"resource_type": "AWS::IAM::Policy"}
        )
        assert upper.matches(qualified) is True
        globbed = supp(
            rule_id="AwsSolutions-IAM*", scope={"resource_type": "AWS::IAM::Policy"}
        )
        assert globbed.matches(qualified) is True
        other = supp(
            rule_id="AwsSolutions-IAM4", scope={"resource_type": "AWS::IAM::Policy"}
        )
        assert other.matches(qualified) is False

    def test_the_same_scoped_entry_without_a_scope_does_not_match_the_base(
        self, fake_engine
    ):
        qualified = finding(
            scanner=fake_engine,
            rule_id="AwsSolutions-IAM5[Resource::*]",
            resource_type="AWS::IAM::Policy",
        )
        assert supp(rule_id="AwsSolutions-IAM5").matches(qualified) is False

    def test_scoped_entry_with_an_unqualified_other_id_does_not_match(
        self, fake_engine
    ):
        entry = supp(rule_id="B999", scope={"resource_type": "T"})
        assert (
            entry.matches(
                finding(scanner=fake_engine, rule_id="B602", resource_type="T")
            )
            is False
        )

    def test_scoped_entry_for_a_scanner_with_no_hooks_has_no_base_split(self):
        entry = supp(rule_id="Rule", scope={"resource_type": "T"})
        qualified = finding(
            scanner="unregistered", rule_id="Rule[Resource::*]", resource_type="T"
        )
        assert entry.matches(qualified) is False

    def test_scoped_entry_with_no_finding_scanner_has_no_base_split(self):
        # scanner is required on a finding; model_construct builds one without
        raw = FlatVulnerability.model_construct(
            id="f",
            title="t",
            description="d",
            severity="HIGH",
            scanner=None,
            scanner_type="SAST",
            rule_id="Rule[Resource::*]",
            file_path="a.py",
            resource_type="T",
        )
        entry = supp(rule_id="Rule", scope={"resource_type": "T"})
        assert entry.matches(raw) is False

    def test_helper_and_method_disagree_on_a_bracketed_id(self):
        """``_rule_id_matches`` has no exact-text step; the method does."""
        bracketed = "Rule[Resource::*]"
        assert _rule_id_matches(bracketed, bracketed) is False
        assert supp(rule_id=bracketed).matches(finding(rule_id=bracketed)) is True

    @pytest.mark.parametrize(
        "find_rule,sup_rule,expected",
        [
            (None, "B602", False),
            ("B602", "b602", True),
            ("B602", "B6*", True),
            ("B602", "B7*", False),
            ("B602", "", False),
            ("", "", True),
            ("", "*", True),
        ],
    )
    def test_rule_id_helper(self, find_rule, sup_rule, expected):
        assert _rule_id_matches(find_rule, sup_rule) is expected


# ---------------------------------------------------------------------------
# path
# ---------------------------------------------------------------------------


class TestPath:
    @pytest.mark.parametrize(
        "pattern,path,expected",
        [
            # literal, case-sensitive
            ("src/app.py", "src/app.py", True),
            ("src/app.py", "SRC/app.py", False),
            ("src/app.py", "src/App.py", False),
            ("src/app.py", "other/src/app.py", False),
            ("src/app.py", "src/app.pyc", False),
            # * is not stopped by a separator
            ("src/*.py", "src/app.py", True),
            ("src/*.py", "src/sub/deep/app.py", True),
            ("src/*.py", "src/app.txt", False),
            ("*.py", "a/b/c.py", True),
            # ? is one character, separators included
            ("src/?.py", "src/a.py", True),
            ("src/?.py", "src/ab.py", False),
            ("src?a.py", "src/a.py", True),
            # [set] and [!set]
            ("src/[ab].py", "src/a.py", True),
            ("src/[ab].py", "src/c.py", False),
            ("src/[!ab].py", "src/c.py", True),
            ("src/[!ab].py", "src/a.py", False),
            # ** = zero or more whole components
            ("src/**/*.py", "src/app.py", True),
            ("src/**/*.py", "src/a/b/app.py", True),
            ("src/**/*.py", "lib/app.py", False),
            ("**/app.py", "app.py", True),
            ("**/app.py", "a/b/app.py", True),
            ("**/app.py", "a/b/app.pyc", False),
            ("**", "a/b/c.py", True),
            ("**", "x", True),
            ("src/**", "src/a/b.py", True),
            ("src/**", "src", True),
            ("src/**", "srcx/a.py", False),
            ("a/**/b/**/c", "a/b/c", True),
            ("a/**/b/**/c", "a/x/y/b/z/c", True),
            ("a/**/b/**/c", "a/x/y/c", False),
            # ** inside a longer component is an ordinary *
            ("src/**.py", "src/app.py", True),
            ("src/**.py", "src/sub/app.py", False),
            ("src/foo**", "src/foobar", True),
            # leading and trailing slashes beside ** are absorbed
            ("/**/x", "a/x", True),
            ("tests/**/", "tests/a.py", True),
            ("tests/**/", "tests", True),
            ("a/**/**/b", "a/b", True),
            ("a/**/**/b", "a/x/y/b", True),
            # a trailing / names the directory (the bare-directory rule, issue
            # #894): the files below it match, a file of that name does not
            ("build/", "build/x.py", True),
            ("build/", "build", False),
            ("build/*", "build/x.py", True),
            ("build/**/*", "build/x/y.py", True),
            ("build/**/*", "build", False),
            # patterns that name no path
            ("", "a.py", False),
            (".", "a.py", False),
            ("./", "a.py", False),
            (".\\", "a.py", False),
            (".", ".", False),
            # a backslash in the pattern is a separator; in the path it is a name
            ("src\\app.py", "src/app.py", True),
            ("src\\app.py", "src\\app.py", False),
            ("src/app.py", "src\\app.py", False),
            ("src\\**\\*.py", "src/a/b.py", True),
            # a pattern with glob characters also names the file spelled so
            ("app/[id]/page.tsx", "app/[id]/page.tsx", True),
            ("app/[id]/page.tsx", "app/i/page.tsx", True),
            ("app/[id]/page.tsx", "app/x/page.tsx", False),
            ("a*b.py", "a*b.py", True),
            ("a?b.py", "a?b.py", True),
            # unicode: code points, no normalization, no case folding
            ("src/café.py", "src/café.py", True),
            ("src/caf?.py", "src/café.py", True),
            ("src/caf?.py", "src/café.py", False),
            ("src/café.py", "src/café.py", False),
            ("src/CAFÉ.py", "src/café.py", False),
            ("日本/*.py", "日本/a.py", True),
            ("日本/*.py", "中国/a.py", False),
            ("src/?.py", "src/😀.py", True),
            ("src/*.py", "src/😀/b.py", True),
            ("src/**/*.py", "src/日本/😀.py", True),
            # whitespace is kept
            ("src/a b.py", "src/a b.py", True),
            ("src/a b.py", "src/a  b.py", False),
            ("src/a*", " src/a", False),
            # surrogates: the report's record form and the name itself
            ("secr?t.py", "secr\udce9t.py", True),
            ("secr\udce9t.py", "secr\udce9t.py", True),
            ("secrxt.py", "secr\udce9t.py", False),
        ],
    )
    def test_path_pattern(self, pattern, path, expected):
        entry = supp(path=pattern)
        assert entry.matches(finding(file_path=path)) is expected
        assert entry.matches_path(path) is expected
        assert file_path_matches(path, pattern) is expected
        assert _path_pattern_matches(path, pattern) is expected

    @pytest.mark.parametrize("pattern", ["**", "*", "src/*", "", ".", "a.py"])
    def test_a_finding_with_no_file_path_never_matches(self, pattern):
        entry = supp(path=pattern)
        assert entry.matches(finding(file_path=None)) is False
        assert entry.matches_path(None) is False
        assert file_path_matches(None, pattern) is False

    def test_an_empty_file_path(self):
        assert supp(path="*").matches(finding(file_path="")) is True
        assert supp(path="**").matches(finding(file_path="")) is True
        assert supp(path="a").matches(finding(file_path="")) is False
        assert supp(path="").matches(finding(file_path="")) is False

    @pytest.mark.parametrize(
        "ignore,path,expected",
        [
            ("vendor/", "vendor/x.py", True),
            ("vendor/", "vendor/a/b.py", True),
            ("vendor/", "vendor", False),
            ("vendor/", "other/vendor/x.py", False),
            ("vendor\\", "vendor/x.py", True),
            ("vendor", "vendor", True),
            # the bare-directory rule (issue #894): a glob-free name is the
            # directory too
            ("vendor", "vendor/x.py", True),
            ("vendor/**", "vendor/x.py", True),
            ("vendor/*", "vendor/x.py", True),
            ("", "a.py", False),
            (".", "a.py", False),
            ("./", "a.py", False),
        ],
    )
    def test_ignore_path_reads_a_trailing_slash_as_its_directory(
        self, ignore, path, expected
    ):
        assert ignore_path_matches(path, ignore) is expected

    def test_ignore_path_with_no_file_path(self):
        assert ignore_path_matches(None, "vendor/") is False


# ---------------------------------------------------------------------------
# lines
# ---------------------------------------------------------------------------


def line_range_oracle(sup_start, sup_end, f_start, f_end):
    """The overlap rule as the matcher states it, for the grid below."""
    if sup_start is None and sup_end is None:
        return True
    if f_start is None:
        return False
    finding_end = f_end if f_end is not None else f_start
    if sup_start is not None and sup_end is None:
        return finding_end >= sup_start
    if sup_start is None and sup_end is not None:
        return finding_end <= sup_end
    return (f_start <= (sup_end or 0)) and (finding_end >= (sup_start or 0))


class TestLines:
    @pytest.mark.parametrize(
        "sup,find,expected",
        [
            # no bounds: any lines, none included
            ((None, None), (None, None), True),
            ((None, None), (5, 9), True),
            # bounds with no finding line: no match, whatever the bound
            ((5, None), (None, None), False),
            ((None, 5), (None, None), False),
            ((5, 9), (None, None), False),
            ((5, 9), (None, 7), False),
            # start only: open ended, the finding's END decides
            ((5, None), (5, 5), True),
            ((5, None), (4, 4), False),
            ((5, None), (1, 5), True),
            ((5, None), (1, 4), False),
            ((5, None), (100, 200), True),
            ((5, None), (4, None), False),
            ((5, None), (5, None), True),
            # end only: the finding's END decides, from the top of the file
            ((None, 5), (5, 5), True),
            ((None, 5), (6, 6), False),
            ((None, 5), (1, 5), True),
            ((None, 5), (1, 6), False),
            ((None, 5), (3, None), True),
            ((None, 5), (6, None), False),
            # both: closed-interval overlap
            ((5, 9), (5, 9), True),
            ((5, 9), (9, 12), True),
            ((5, 9), (10, 12), False),
            ((5, 9), (1, 5), True),
            ((5, 9), (1, 4), False),
            ((5, 9), (1, 20), True),
            ((5, 9), (6, 7), True),
            ((5, 9), (7, None), True),
            ((5, 9), (4, None), False),
            ((5, 5), (5, 5), True),
            ((5, 5), (4, 6), True),
            # a finding with an inverted range: its END is the smaller number
            ((15, 15), (20, 10), False),
            ((5, 12), (20, 10), False),
            ((12, 30), (20, 10), False),
            ((5, 30), (20, 10), True),
            # zero and negative lines
            ((0, 0), (0, 0), True),
            ((0, 0), (1, 1), False),
            ((0, None), (0, 0), True),
            ((None, 0), (0, 0), True),
            ((None, 0), (1, 1), False),
            ((-5, 5), (-10, -5), True),
            ((-5, 5), (-10, -6), False),
            # large
            ((10**18, None), (10**18, 10**18), True),
            ((10**18, None), (10**18 - 1, 10**18 - 1), False),
            ((1, 10**18), (10**18, 10**18 + 5), True),
        ],
    )
    def test_single_cases(self, sup, find, expected):
        entry = supp(line_start=sup[0], line_end=sup[1])
        f = finding(line_start=find[0], line_end=find[1])
        assert entry._line_range_matches(f) is expected
        assert module_line_range_matches(f, entry) is expected
        assert entry.matches(f) is expected

    def test_the_full_grid_agrees_with_the_overlap_rule_and_both_spellings(self):
        sup_bounds = [None, 0, 1, 5, 9, 10]
        find_bounds = [None, 0, 1, 5, 9, 10, 20]
        checked = 0
        for s_start, s_end in itertools.product(sup_bounds, repeat=2):
            if s_start is not None and s_end is not None and s_end < s_start:
                continue  # the model refuses it
            entry = supp(line_start=s_start, line_end=s_end)
            for f_start, f_end in itertools.product(find_bounds, repeat=2):
                f = finding(line_start=f_start, line_end=f_end)
                expected = line_range_oracle(s_start, s_end, f_start, f_end)
                assert entry._line_range_matches(f) is expected, (
                    s_start,
                    s_end,
                    f_start,
                    f_end,
                )
                assert module_line_range_matches(f, entry) is expected
                checked += 1
        assert checked == 26 * 49

    def test_a_line_end_before_the_start_is_refused_at_construction(self):
        with pytest.raises(ValueError):
            supp(line_start=9, line_end=5)


# ---------------------------------------------------------------------------
# package fields
# ---------------------------------------------------------------------------


class TestPackage:
    @pytest.mark.parametrize(
        "field,pattern,value,expected",
        [
            ("package_name", "lodash", "lodash", True),
            ("package_name", "LODASH", "lodash", True),
            ("package_name", "lodash", "Lodash", True),
            ("package_name", "lod*", "lodash-es", True),
            ("package_name", "lodash", "lodash-es", False),
            ("package_name", "@scope/*", "@scope/pkg", True),
            ("package_name", "@scope/*", "@scope/a/b", True),
            ("package_name", "?", "a", True),
            ("package_name", "ä*", "ÄB", True),
            # a bracketed pattern is a class, not its own text
            ("package_name", "a[b]", "ab", True),
            ("package_name", "a[b]", "a[b]", False),
            ("package_version", "1.2.3", "1.2.3", True),
            ("package_version", "1.2.3", "1.2.30", False),
            ("package_version", "1.*", "1.2.3", True),
            ("package_version", "1.*", "10.2.3", False),
            ("package_version", "1.2.?", "1.2.3", True),
            ("package_version", "2.0.0-RC1", "2.0.0-rc1", True),
            ("package_version", "[0-9]*", "1.0", True),
            ("package_version", "*", "", True),
            # package_path reads as a path pattern: case-sensitive, ** aware
            ("package_path", "node_modules/a", "node_modules/a", True),
            ("package_path", "node_modules/a", "Node_modules/a", False),
            (
                "package_path",
                "node_modules/**/brace-expansion",
                "node_modules/a/node_modules/brace-expansion",
                True,
            ),
            (
                "package_path",
                "node_modules/**/brace-expansion",
                "node_modules/brace-expansion",
                True,
            ),
            (
                "package_path",
                "node_modules/**/brace-expansion",
                "lib/brace-expansion",
                False,
            ),
            ("package_path", "node_modules/*", "node_modules/a/b", True),
            ("package_path", "pkg\\a", "pkg/a", True),
            ("package_path", "pkg/", "pkg/a", False),
        ],
    )
    def test_each_field(self, field, pattern, value, expected):
        entry = supp(**{field: pattern})
        assert entry.matches(finding(**{field: value})) is expected

    @pytest.mark.parametrize(
        "field", ["package_name", "package_version", "package_path"]
    )
    def test_a_finding_without_the_field_never_matches_a_set_field(self, field):
        entry = supp(**{field: "*"})
        assert entry.matches(finding(**{field: None})) is False

    def test_an_unset_field_ignores_the_finding_value(self):
        entry = supp()
        assert entry.matches(finding(package_name=None)) is True
        assert entry.matches(finding(package_name="x", package_version="1")) is True

    def test_all_set_fields_must_match(self):
        entry = supp(package_name="lodash", package_version="4.*", package_path="a/**")
        good = finding(
            package_name="lodash", package_version="4.17.21", package_path="a/b"
        )
        assert entry.matches(good) is True
        for override in (
            {"package_name": "other"},
            {"package_version": "5.0.0"},
            {"package_path": "b/a"},
            {"package_name": None},
            {"package_version": None},
            {"package_path": None},
        ):
            assert entry.matches(good.model_copy(update=override)) is False, override

    def test_a_blank_package_field_cannot_be_constructed(self):
        for field in ("package_name", "package_version", "package_path"):
            with pytest.raises(ValueError):
                supp(**{field: " "})


# ---------------------------------------------------------------------------
# scope
# ---------------------------------------------------------------------------


class TestScopeValueMatches:
    @pytest.mark.parametrize(
        "value,pattern,case_sensitive,expected",
        [
            ("a/b", "a/b", True, True),
            ("a/b", "A/B", True, False),
            ("a/b", "A/B", False, True),
            ("A/B", "a/b", False, True),
            ("a/b/c", "a/*", True, True),
            ("a/b/c", "a/?", True, False),
            ("a/b", "a/?", True, True),
            ("", "", True, True),
            ("", "*", True, True),
            ("x", "", True, False),
            # [ is escaped, so a class is never read: the pattern is its own text
            ("Stack/Thing[0]/Resource", "Stack/Thing[0]/Resource", True, True),
            ("Stack/Thing0/Resource", "Stack/Thing[0]/Resource", True, False),
            ("Stack/Thing[0]/Resource", "Stack/Thing[*]/Resource", True, True),
            ("Stack/Thing[12]/Resource", "Stack/Thing[*]/Resource", True, True),
            ("a", "[a]", True, False),
            ("[a]", "[a]", True, True),
            ("[!a]", "[!a]", True, True),
            ("b", "[!a]", True, False),
            # ] alone is ordinary
            ("a]", "a]", True, True),
            ("a]", "a?", True, True),
            # case folding is lower(), not casefold()
            ("STRASSE", "straße", False, False),
            ("İSTANBUL", "istanbul", False, False),
            ("ÄB", "äb", False, True),
            ("ÄB", "äb", True, False),
            # a literal wins before any glob reading
            ("a*b", "a*b", True, True),
            ("axb", "a*b", True, True),
        ],
    )
    def test_cases(self, value, pattern, case_sensitive, expected):
        assert (
            scope_value_matches(value, pattern, case_sensitive=case_sensitive)
            is expected
        )


class TestScope:
    def test_resource_id_is_case_sensitive_and_literal_first(self):
        entry = supp(scope={"resource_id": "Stack/Role/Resource"})
        assert entry.matches(finding(resource_id="Stack/Role/Resource")) is True
        assert entry.matches(finding(resource_id="stack/role/resource")) is False
        assert entry.matches(finding(resource_id=None)) is False

    def test_resource_type_is_case_insensitive(self):
        entry = supp(scope={"resource_type": "AWS::IAM::Policy"})
        assert entry.matches(finding(resource_type="aws::iam::policy")) is True
        assert entry.matches(finding(resource_type="AWS::IAM::Role")) is False
        assert entry.matches(finding(resource_type=None)) is False

    def test_both_universal_keys_must_match(self):
        entry = supp(scope={"resource_id": "S/*", "resource_type": "T"})
        assert entry.matches(finding(resource_id="S/a", resource_type="t")) is True
        assert entry.matches(finding(resource_id="X/a", resource_type="t")) is False
        assert entry.matches(finding(resource_id="S/a", resource_type="u")) is False
        assert entry.matches(finding(resource_id="S/a", resource_type=None)) is False
        assert entry.matches(finding(resource_id=None, resource_type="t")) is False

    def test_resource_id_sugar_folds_into_the_scope(self):
        entry = supp(resource_id="S/*")
        assert entry.scope is not None and entry.scope.resource_id == "S/*"
        assert entry.matches(finding(resource_id="S/a")) is True
        assert entry.matches(finding(resource_id="T/a")) is False
        assert entry.matches(finding(resource_id=None)) is False

    def test_an_equal_sugar_and_scope_value_is_accepted(self):
        entry = supp(resource_id="S/a", scope={"resource_id": "S/a"})
        assert entry.matches(finding(resource_id="S/a")) is True

    def test_sugar_beside_a_scope_without_resource_id_fills_it(self):
        entry = supp(resource_id="S/a", scope={"resource_type": "T"})
        assert entry.scope is not None and entry.scope.resource_id == "S/a"
        assert entry.matches(finding(resource_id="S/a", resource_type="T")) is True
        assert entry.matches(finding(resource_id="S/b", resource_type="T")) is False

    def test_disagreeing_sugar_and_scope_is_refused(self):
        with pytest.raises(ValueError):
            supp(resource_id="a", scope={"resource_id": "b"})

    def test_disagreeing_pair_kept_from_a_results_file_never_matches(self):
        entry = stored(resource_id="a", scope={"resource_id": "b"})
        assert entry.matches(finding(resource_id="a")) is False
        assert entry.matches(finding(resource_id="b")) is False

    @pytest.mark.parametrize(
        "scope",
        [
            {},
            {"resource_id": " "},
            {"resource_type": ""},
            {"engines": {}},
            {"engines": {"fake-engine": {}}},
            {"resource_id": "a", "bogus": 1},
        ],
    )
    def test_a_scope_kept_from_a_results_file_that_selects_nothing_never_matches(
        self, scope, fake_engine
    ):
        entry = stored(scope=scope)
        assert entry.matches(finding(resource_id="a", resource_type="T")) is False
        assert (
            entry.matches(finding(resource_id="a", scanner=fake_engine, rule_id="m"))
            is False
        )

    def test_engines_enumerate_the_covered_scanners(self, fake_engine):
        entry = supp(rule_id=None, scope={"engines": {fake_engine: {"marker": "R1"}}})
        assert entry.matches(finding(scanner=fake_engine, rule_id="R1")) is True
        assert entry.matches(finding(scanner=fake_engine, rule_id="R2")) is False
        assert entry.matches(finding(scanner="bandit", rule_id="R1")) is False

    def test_a_finding_with_no_scanner_matches_no_engine_scope(self, fake_engine):
        entry = supp(scope={"engines": {fake_engine: {"marker": "R1"}}})
        raw = FlatVulnerability.model_construct(
            id="f",
            title="t",
            description="d",
            severity="HIGH",
            scanner=None,
            scanner_type="SAST",
            rule_id="R1",
            file_path="a.py",
        )
        assert entry.matches(raw) is False

    def test_an_engine_with_no_hooks_fails_closed_and_warns_once_per_name(self):
        entry = supp(scope={"engines": {"ghost": {"k": "v"}}})
        warned: set = set()
        assert entry.matches(finding(scanner="ghost"), warned_engines=warned) is False
        assert warned == {"ghost"}
        assert entry.matches(finding(scanner="ghost"), warned_engines=warned) is False
        assert warned == {"ghost"}

    def test_the_no_engine_fallback_set_is_used_when_none_is_passed(self):
        entry = supp(scope={"engines": {"ghost": {"k": "v"}}})
        assert entry.matches(finding(scanner="ghost")) is False
        assert registry._NO_ENGINE_WARNED == {"ghost"}

    def test_the_engine_block_is_reached_only_after_the_universal_keys(self):
        entry = supp(scope={"resource_id": "S/*", "engines": {"ghost": {"k": "v"}}})
        warned: set = set()
        assert (
            entry.matches(
                finding(scanner="ghost", resource_id="X/a"), warned_engines=warned
            )
            is False
        )
        assert warned == set()
        assert (
            entry.matches(
                finding(scanner="ghost", resource_id="S/a"), warned_engines=warned
            )
            is False
        )
        assert warned == {"ghost"}

    def test_an_unlisted_scanner_never_reaches_the_engine_block(self, fake_engine):
        entry = supp(scope={"engines": {"ghost": {"k": "v"}}})
        warned: set = set()
        assert (
            entry.matches(finding(scanner=fake_engine), warned_engines=warned) is False
        )
        assert warned == set()


# ---------------------------------------------------------------------------
# symbol
# ---------------------------------------------------------------------------


class TestSymbol:
    def test_no_resolver_matches_nothing(self):
        assert supp(symbol="Cls.method").matches(finding()) is False

    def test_the_resolver_decides_and_gets_the_finding_span(self):
        yes, no = RecordingResolver(True), RecordingResolver(False)
        entry = supp(symbol="Cls.method")
        assert entry.matches(finding(), yes) is True
        assert entry.matches(finding(), no) is False
        assert yes.calls == [("src/app.py", 10, 12, "Cls.method")]
        assert no.calls == [("src/app.py", 10, 12, "Cls.method")]

    def test_a_missing_line_end_is_passed_through_as_none(self):
        resolver = RecordingResolver(True)
        supp(symbol="f").matches(finding(line_start=7, line_end=None), resolver)
        assert resolver.calls == [("src/app.py", 7, None, "f")]

    def test_the_resolver_is_asked_last(self):
        resolver = RecordingResolver(True)
        entry = supp(symbol="f", rule_id="B999")
        assert entry.matches(finding(), resolver) is False
        assert resolver.calls == []
        entry = supp(symbol="f", path="lib/**")
        assert entry.matches(finding(), resolver) is False
        entry = supp(symbol="f", line_start=100)
        assert entry.matches(finding(), resolver) is False
        entry = supp(symbol="f", package_name="x")
        assert entry.matches(finding(), resolver) is False
        entry = supp(symbol="f", scope={"resource_type": "T"})
        assert entry.matches(finding(), resolver) is False
        assert resolver.calls == []

    def test_an_expired_symbol_entry_never_asks_the_resolver(self):
        resolver = RecordingResolver(True)
        entry = supp(symbol="f", expires="2000-01-01")
        assert entry.matches(finding(), resolver) is False
        assert resolver.calls == []

    def test_a_resolver_is_ignored_by_an_entry_with_no_symbol(self):
        resolver = RecordingResolver(False)
        assert supp().matches(finding(), resolver) is True
        assert resolver.calls == []

    def test_a_symbol_kept_as_an_environment_reference_never_applies(self):
        resolver = RecordingResolver(True)
        entry = stored(symbol="${SYMBOL}")
        assert entry.matches(finding(), resolver) is False
        assert resolver.calls == []


# ---------------------------------------------------------------------------
# expiration and unknown keys
# ---------------------------------------------------------------------------


class TestExpiryAndUnknownKeys:
    def test_far_dates(self):
        assert supp(expires="2000-01-01").matches(finding()) is False
        assert supp(expires="2999-12-31").matches(finding()) is True

    def test_the_expiration_day_itself_is_already_expired(self, today):
        today(2030, 6, 15)
        assert supp(expires="2030-06-14").matches(finding()) is False
        assert supp(expires="2030-06-15").matches(finding()) is False
        assert supp(expires="2030-06-16").matches(finding()) is True

    def test_the_deprecated_alias_reads_the_same(self, today):
        today(2030, 6, 15)
        assert supp(expiration="2030-06-15").matches(finding()) is False
        assert supp(expiration="2030-06-16").matches(finding()) is True

    @pytest.mark.parametrize("bad", ["not-a-date", "", "2030-13-01", "06/15/2030"])
    def test_an_unreadable_date_kept_from_a_results_file_never_applies(self, bad):
        entry = stored(expires=bad)
        assert entry.is_expired is True
        assert entry.matches(finding()) is False

    def test_an_entry_with_an_unknown_key_kept_from_a_results_file_never_applies(
        self,
    ):
        entry = stored(bogus="x", rule_id="B602")
        assert entry.has_unknown_keys is True
        assert entry.matches(finding()) is False

    def test_a_misspelled_rule_id_does_not_become_match_all(self):
        entry = AshSuppression.model_validate(
            {"ruleId": "B101", "path": "**", "reason": "r"},
            context={TOLERATE_STORED_CONFIG: []},
        )
        assert entry.rule_id is None
        assert entry.matches(finding(rule_id="B602")) is False

    def test_expiry_and_unknown_keys_win_over_every_other_field(self):
        assert supp(expires="2000-01-01", rule_id="B602").matches(finding()) is False
        assert stored(bogus=1).matches(finding()) is False


# ---------------------------------------------------------------------------
# should_suppress_finding and the thin wrappers
# ---------------------------------------------------------------------------


class TestShouldSuppress:
    def test_empty_and_no_match(self):
        assert should_suppress_finding(finding(), []) == (False, None)
        assert should_suppress_finding(finding(), [supp(rule_id="X")]) == (False, None)

    def test_returns_the_first_matching_entry_object(self):
        a, b, c = supp(rule_id="NOPE"), supp(rule_id="B6*"), supp(rule_id="B602")
        suppressed, hit = should_suppress_finding(finding(), [a, b, c])
        assert suppressed is True
        assert hit is b

    def test_duplicate_entries_return_the_first(self):
        first, second = supp(rule_id="B602"), supp(rule_id="B602")
        assert should_suppress_finding(finding(), [first, second])[1] is first
        assert should_suppress_finding(finding(), [second, first])[1] is second

    def test_expired_and_unknown_key_entries_are_skipped_to_a_later_one(self):
        expired = supp(rule_id="B602", expires="2000-01-01")
        unknown = stored(rule_id="B602", bogus=1)
        live = supp(rule_id="B602")
        suppressed, hit = should_suppress_finding(finding(), [expired, unknown, live])
        assert suppressed is True and hit is live
        assert should_suppress_finding(finding(), [expired, unknown]) == (False, None)

    def test_large_n_keeps_list_order(self):
        entries = [supp(rule_id=f"R{i}") for i in range(1000)]
        entries[777] = supp(rule_id="B602")
        entries[900] = supp(rule_id="B6*")
        suppressed, hit = should_suppress_finding(finding(), entries)
        assert suppressed is True and hit is entries[777]
        del entries[777]
        assert should_suppress_finding(finding(), entries)[1] is entries[899]

    def test_threads_resolver_and_warned_engines(self):
        resolver = RecordingResolver(True)
        warned: set = set()
        entries = [
            supp(scope={"engines": {"ghost": {"k": "v"}}}),
            supp(symbol="f"),
        ]
        suppressed, hit = should_suppress_finding(
            finding(scanner="ghost"),
            entries,
            symbol_resolver=resolver,
            warned_engines=warned,
        )
        assert suppressed is True and hit is entries[1]
        assert warned == {"ghost"}
        assert resolver.calls == [("src/app.py", 10, 12, "f")]

    def test_where_does_not_change_the_answer(self):
        entries = [supp(rule_id="B602")]
        assert (
            should_suppress_finding(finding(), entries, where="elsewhere")[1]
            is (entries[0])
        )

    def test_matches_suppression_is_the_method(self):
        resolver = RecordingResolver(True)
        entry = supp(symbol="f")
        assert matches_suppression(finding(), entry, resolver) is True
        assert matches_suppression(finding(), entry) is False
        warned: set = set()
        ghost = supp(scope={"engines": {"ghost": {"k": "v"}}})
        assert (
            matches_suppression(finding(scanner="ghost"), ghost, None, warned) is False
        )
        assert warned == {"ghost"}


class TestUnconvertedInputAndActiveIgnorePaths:
    def test_an_entry_accepts_only_for_the_exact_rule_id(self):
        rule = UNCONVERTED_INPUT_RULE
        assert accepting_unconverted_input("a/b.zip", [supp(rule_id=rule, path="a/*")])
        assert accepting_unconverted_input(
            "a/b.zip", [supp(rule_id=rule.upper(), path="a/*")]
        )
        assert (
            accepting_unconverted_input("a/b.zip", [supp(rule_id="ash-*", path="a/*")])
            is None
        )
        assert accepting_unconverted_input("a/b.zip", [supp(path="a/*")]) is None
        assert accepting_unconverted_input("a/b.zip", None) is None
        assert accepting_unconverted_input("a/b.zip", []) is None

    def test_it_reads_the_path_as_matches_path_does(self):
        rule = UNCONVERTED_INPUT_RULE
        # "a/" names the directory and covers what is below it (the
        # bare-directory rule, issue #894), as matches_path reads it.
        assert accepting_unconverted_input("a/b.zip", [supp(rule_id=rule, path="a/")])
        assert accepting_unconverted_input("a/b.zip", [supp(rule_id=rule, path="**")])
        assert (
            accepting_unconverted_input("a/b.zip", [supp(rule_id=rule, path="c/")])
            is None
        )
        assert (
            accepting_unconverted_input("a/b.zip", [supp(rule_id=rule, path="c/*")])
            is None
        )

    def test_client_supplied_expired_and_unknown_entries_accept_nothing(self):
        rule = UNCONVERTED_INPUT_RULE
        client = supp(rule_id=rule, path="**", client_supplied=True)
        expired = supp(rule_id=rule, path="**", expires="2000-01-01")
        unknown = stored(rule_id=rule, path="**", bogus=1)
        live = supp(rule_id=rule, path="**")
        assert accepting_unconverted_input("x.zip", [client, expired, unknown]) is None
        assert (
            accepting_unconverted_input("x.zip", [client, expired, unknown, live])
            is live
        )

    def test_only_the_path_rule_and_state_take_part(self):
        rule = UNCONVERTED_INPUT_RULE
        scoped = supp(rule_id=rule, path="**", package_name="nope", line_start=99)
        assert accepting_unconverted_input("x.zip", [scoped]) is scoped

    def test_active_ignore_paths_drops_expired_and_unknown_keys_in_order(self):
        a = IgnorePathWithReason(path="a/**", reason="r")
        b = IgnorePathWithReason(path="b/**", reason="r", expires="2000-01-01")
        c = IgnorePathWithReason.model_validate(
            {"path": "c/**", "reason": "r", "bogus": 1},
            context={TOLERATE_STORED_CONFIG: []},
        )
        d = IgnorePathWithReason(path="d/**", reason="r", expires="2999-12-31")
        kept = active_ignore_paths([a, b, c, d])
        assert kept == [a, d]
        assert kept[0] is a and kept[1] is d
        assert active_ignore_paths(None) == []
        assert active_ignore_paths([]) == []


# ---------------------------------------------------------------------------
# the generated corpus
# ---------------------------------------------------------------------------

CORPUS_RULES_FINDING = [None, "B602", "b602", "AWS-IAM5[Action::x]"]
CORPUS_PATHS_FINDING = [None, "src/a.py", "src/sub/b.py", "tests/t.py", "src/café.py"]
CORPUS_LINES_FINDING = [(None, None), (5, None), (5, 5), (8, 20)]
CORPUS_PACKAGES_FINDING = [None, "Lodash"]

CORPUS_RULES_SUPP = [None, "B602", "B6*", "aws-*"]
CORPUS_PATHS_SUPP = ["src/*.py", "src/**/*.py", "**", "tests/t.py", "build/"]
CORPUS_LINES_SUPP = [(None, None), (5, None), (None, 10), (6, 9)]
CORPUS_PACKAGES_SUPP = [None, "lod*"]


def corpus_findings():
    return [
        finding(
            rule_id=rule,
            file_path=path,
            line_start=lines[0],
            line_end=lines[1],
            package_name=package,
        )
        for rule, path, lines, package in itertools.product(
            CORPUS_RULES_FINDING,
            CORPUS_PATHS_FINDING,
            CORPUS_LINES_FINDING,
            CORPUS_PACKAGES_FINDING,
        )
    ]


def corpus_suppressions():
    return [
        supp(
            rule_id=rule,
            path=path,
            line_start=lines[0],
            line_end=lines[1],
            package_name=package,
        )
        for rule, path, lines, package in itertools.product(
            CORPUS_RULES_SUPP,
            CORPUS_PATHS_SUPP,
            CORPUS_LINES_SUPP,
            CORPUS_PACKAGES_SUPP,
        )
    ]


def corpus_outcomes(match):
    """``'1'``/``'0'`` per (finding, suppression) pair, findings outermost."""
    suppressions = corpus_suppressions()
    return "".join(
        "1" if match(f, s) else "0" for f in corpus_findings() for s in suppressions
    )


def corpus_first_hits(first_hit):
    """The index of the first suppression that covers each finding, or -1."""
    suppressions = corpus_suppressions()
    out = []
    for f in corpus_findings():
        hit = first_hit(f, suppressions)
        out.append(-1 if hit is None else suppressions.index(hit))
    return ",".join(str(i) for i in out)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("ascii")).hexdigest()


#: Pinned from the unmodified code. A replacement implementation is run through
#: corpus_outcomes / corpus_first_hits and must produce these exactly.
GOLDEN_CORPUS_PAIRS = 25600
GOLDEN_CORPUS_MATCHES = 2970
GOLDEN_CORPUS_OUTCOMES_SHA256 = "5fbc0b8a353bc0c8467ab724bab6f690d6ec6cd133d16c4d4df4df84f70566a7"  # pragma: allowlist secret
GOLDEN_CORPUS_FIRST_HITS_SHA256 = "6121a274904d957296d52a38d6a54a6770a5ba526569c5ba23d8c3fb93d8f7d6"  # pragma: allowlist secret


class TestGeneratedCorpus:
    def test_the_corpus_has_the_pinned_shape(self):
        assert len(corpus_findings()) == 160
        assert len(corpus_suppressions()) == 160

    def test_every_pair_outcome(self):
        outcomes = corpus_outcomes(lambda f, s: s.matches(f))
        assert len(outcomes) == GOLDEN_CORPUS_PAIRS
        assert outcomes.count("1") == GOLDEN_CORPUS_MATCHES
        assert _sha256(outcomes) == GOLDEN_CORPUS_OUTCOMES_SHA256

    def test_the_wrapper_agrees_with_the_method_on_every_pair(self):
        by_method = corpus_outcomes(lambda f, s: s.matches(f))
        by_wrapper = corpus_outcomes(lambda f, s: matches_suppression(f, s))
        assert by_wrapper == by_method

    def test_first_match_index_per_finding(self):
        hits = corpus_first_hits(lambda f, ss: should_suppress_finding(f, ss)[1])
        assert _sha256(hits) == GOLDEN_CORPUS_FIRST_HITS_SHA256

    def test_first_match_agrees_with_the_first_true_pair(self):
        suppressions = corpus_suppressions()
        for f in corpus_findings():
            expected = next((s for s in suppressions if s.matches(f)), None)
            suppressed, hit = should_suppress_finding(f, suppressions)
            assert hit is expected
            assert suppressed is (expected is not None)

    def test_an_all_inclusive_entry_covers_exactly_the_findings_with_a_file_path(self):
        everything = supp(path="**")
        for f in corpus_findings():
            assert everything.matches(f) is (f.file_path is not None)

    def test_reversing_the_list_moves_the_hit_to_the_last_true_pair(self):
        suppressions = corpus_suppressions()
        reverse = list(reversed(suppressions))
        for f in corpus_findings():
            expected = next((s for s in reverse if s.matches(f)), None)
            assert should_suppress_finding(f, reverse)[1] is expected
