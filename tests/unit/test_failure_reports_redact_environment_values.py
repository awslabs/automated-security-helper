# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A failing test's report holds no environment value, whatever printed it.

The root conftest's ``pytest_runtest_makereport`` passes every report that did
not pass through ``redact_environment_values`` (tests/utils/env_assertions.py):
each environment value of ``MIN_REDACTED_LENGTH`` characters or more, as
``os.environ`` holds it now or held it when the session started, is replaced
in the report's ``longrepr`` and in its captured sections, by the product's
``redact_values`` rules. So a value a test prints, or a failure explains, does
not reach the terminal or the junit report, however the test reached it.
"""

import json
import logging
import os
import secrets
from collections import Counter
from pathlib import Path
from typing import Dict, List, Literal, Tuple, Union
from urllib.parse import quote

import pytest
from _pytest.reports import TestReport

from tests.utils import env_assertions
from tests.utils.helpers import run_a_child_pytest_under_this_suite

CANARY = "ASH_TEST_BACKSTOP_CANARY"
REMOVED = "ASH_TEST_BACKSTOP_REMOVED"
SHORT = "ASH_TEST_BACKSTOP_SHORT"
NUMBER_NAME = "ASH_TEST_BACKSTOP_NUMBER"
#: Shorter than MIN_REDACTED_LENGTH: such a value is left where it is printed.
SHORT_VALUE = "q7z"


def test_an_environment_value_in_text_is_redacted_and_other_text_is_left(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A value the environment holds is replaced; text it does not hold, and
    a value shorter than MIN_REDACTED_LENGTH, are left."""
    value = "canary-" + secrets.token_hex(16)
    other = "sentinel-" + secrets.token_hex(16)
    monkeypatch.setenv(CANARY, value)
    monkeypatch.setenv(SHORT, SHORT_VALUE)
    text = env_assertions.redacted_environment_values(
        f"{value} beside {other} and {SHORT_VALUE}"
    )
    shown = (value in text, other in text, SHORT_VALUE in text, "<value>" in text)
    assert shown == (False, True, True, True)


def test_a_value_glued_into_a_test_path_keeps_the_report_readable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The backstop sweeps the whole environment, so a common host value
    (USER=runner) glued into a path or module name by "_" must not mangle
    the report: this backstop is the one caller of the product's test-report
    word rule (_redact_for_test_reports), and its output for the CI shape is
    unchanged by the product's strict default. The same value standing alone
    is still replaced."""
    monkeypatch.setenv(CANARY, "runner7")
    text = "test_uv_tool_runner7.py:74: the test_uv_tool_runner7 module raised"
    assert env_assertions.redacted_environment_values(text) == text
    standalone = env_assertions.redacted_environment_values("the user runner7 ran")
    assert "runner7" not in standalone


@pytest.mark.parametrize("word", ["true", "False", "YES", "no", "On", "off"])
def test_a_word_that_carries_no_secret_is_left(
    monkeypatch: pytest.MonkeyPatch, word: str
) -> None:
    """A value that is one of the fixed words of the closed list, in any
    case, is left, so a failure's True and False stay readable."""
    monkeypatch.setenv(CANARY, word)
    left = word in env_assertions.redacted_environment_values(f"assert {word} is x")
    assert left


def test_a_short_value_not_on_the_list_is_redacted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A value of exactly MIN_REDACTED_LENGTH characters that is not one of
    the listed words is replaced, so the list cannot widen into a hole."""
    value = "qz" + secrets.token_hex(1)
    monkeypatch.setenv(CANARY, value)
    held = value in env_assertions.redacted_environment_values(f"a {value} b")
    assert len(value) == env_assertions.MIN_REDACTED_LENGTH and not held


def test_a_value_a_message_escaped_is_redacted_where_a_report_escapes_it_again(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failure shows a string by its repr, so a value the string held
    escaped already (by repr, unicode_escape or JSON, as a message prints a
    value) is printed escaped twice: it is redacted all the same."""
    token = secrets.token_hex(16)
    value = "canary-" + token + "\\t\u00e9"
    monkeypatch.setenv(CANARY, value)
    once = {
        "repr": repr(value)[1:-1],
        "unicode_escape": value.encode("unicode_escape").decode("ascii"),
        "JSON": json.dumps(value)[1:-1],
    }
    if any(repr(text)[1:-1] == text for text in once.values()):
        raise RuntimeError("control: escaping a form again did not change it")
    shown = {
        form: env_assertions.redacted_environment_values(repr(f"holds {text}"))
        for form, text in once.items()
    }
    assert {form: token in text for form, text in shown.items()} == dict.fromkeys(
        once, False
    )


def test_a_value_the_session_started_with_is_redacted_after_it_is_removed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A value os.environ held when the session started is replaced after a
    test removed its variable, as a failure while it is removed prints it.
    The variable is picked from the session-start snapshot, not from the
    environment alone: one set after the session started (pytest sets
    PYTEST_CURRENT_TEST during the call, often the longest value) is not in
    the snapshot, and removing it would leave nothing to redact from. It is
    also picked among values held by exactly one variable: were another
    variable still holding the value, it would be redacted through
    ``os.environ`` and this cell would pass without the snapshot."""
    counts = Counter(os.environ.values())
    name, value = max(
        (
            (name, value)
            for name, value in os.environ.items()
            if value in env_assertions._VALUES_AT_START and counts[value] == 1
        ),
        key=lambda item: len(item[1]),
    )
    monkeypatch.delenv(name)
    # Computed first, asserted as a bool: an assert naming the environment
    # mapping itself would print it on failure.
    still_held = value in os.environ.values()
    assert not still_held, "another variable holds the removed value"
    held = value in env_assertions.redacted_environment_values(f"removed: {value}")
    assert not held


def test_a_fragment_of_a_long_value_is_redacted_whatever_cut_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A report can hold a piece of a value rather than the whole: unittest
    shortens a long repr around a ``[N chars]`` marker, and pytest's
    explanation and line limits can cut a value at a boundary with no marker
    at all. The product replaces pieces beside its own "..." markers; every
    other piece of twelve or more characters of a value of sixteen or more is
    replaced by the fragment pass, whatever stands around it. Text that
    shares no such window survives, and so does a short value's fragment,
    which could be any word."""
    value = "canary-" + secrets.token_hex(16)
    other = "sentinel-" + secrets.token_hex(16)
    short = "shortval-abc"  # 12 characters: below the fragment band
    below = "qq-" + secrets.token_hex(6)  # 15 characters: one below the band
    monkeypatch.setenv(CANARY, value)
    monkeypatch.setenv(SHORT, short)
    monkeypatch.setenv(REMOVED, below)
    shapes = {
        "a unittest-shortened repr": f"x {value[:41]}[99 chars]{value[-5:]} y",
        "a piece cut at a line boundary": f"x {value[10:40]} y",
        "a piece cut mid-word": f"word{value[5:25]}word",
    }
    windows = {
        text[start : start + 12] for text in (value,) for start in range(len(text) - 11)
    }

    def leaks(text: str) -> bool:
        hidden = env_assertions.redacted_environment_values(text)
        return any(window in hidden for window in windows)

    leaked = {shape: leaks(text) for shape, text in shapes.items()}
    assert leaked == dict.fromkeys(shapes, False), leaked
    survivors = env_assertions.redacted_environment_values(
        f"{other} beside {short[:11]} and {below[:12]}"
    )
    assert other in survivors, "text sharing no window was replaced"
    assert short[:11] in survivors, "a short value's fragment was replaced"
    assert below[:12] in survivors, "a fragment of a value below the band was replaced"


def test_a_value_is_redacted_when_the_products_redaction_cannot_be_imported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without the product's _redact_for_test_reports and _printed_forms, a
    report's text and a live log line are redacted all the same, where the
    value is written as it is, and text the environment does not hold is
    left."""
    from automated_security_helper.config import config_validator

    value = "canary-" + secrets.token_hex(16)
    other = "sentinel-" + secrets.token_hex(16)
    monkeypatch.setenv(CANARY, value)
    monkeypatch.delattr(config_validator, "_redact_for_test_reports")
    monkeypatch.delattr(config_validator, "_printed_forms")
    env_assertions._folded_printed_forms.cache_clear()
    try:
        text = env_assertions.redacted_environment_values(f"{value} beside {other}")
        line = env_assertions.EnvironmentValuesRedacted(
            logging.Formatter("%(message)s")
        ).format(
            logging.LogRecord(
                "probe", logging.WARNING, __file__, 1, f"{value} {other}", None, None
            )
        )
    finally:
        env_assertions._folded_printed_forms.cache_clear()
    assert (value in text, other in text, value in line, other in line) == (
        False,
        True,
        False,
        True,
    )


def test_the_form_caches_hold_across_reports(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """pytest rewrites PYTEST_CURRENT_TEST around every test phase, and a
    cache keyed on one tuple of every environment value missed on every
    report, recomputing every value's printed forms and fragment windows
    each time: the heavy caches are keyed on the stable values, with the
    volatile few computed fresh, so two redactions under different
    PYTEST_CURRENT_TEST values hit the caches. The volatile values are still
    redacted exactly like the rest: only the caching is split."""
    value = "canary-" + secrets.token_hex(16)
    monkeypatch.setenv(CANARY, value)
    env_assertions._escaped_once_more.cache_clear()
    env_assertions._fragment_windows.cache_clear()
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "tests/a.py::test_one (call)")
    env_assertions.redacted_environment_values("plain text")
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "tests/a.py::test_two (call)")
    env_assertions.redacted_environment_values("plain text")
    hits = (
        env_assertions._escaped_once_more.cache_info().hits,
        env_assertions._fragment_windows.cache_info().hits,
    )
    assert all(count >= 1 for count in hits), (
        "the form caches missed across reports",
        hits,
    )
    planted = "pct-" + secrets.token_hex(16)
    monkeypatch.setenv("PYTEST_CURRENT_TEST", planted)
    shown = env_assertions.redacted_environment_values(f"holds {planted} and {value}")
    assert planted not in shown and value not in shown, (
        "a volatile value stopped being redacted",
        "<value>" in shown,
    )


def _report(
    outcome: Literal["passed", "failed", "skipped"],
    longrepr: Union[None, str, Tuple[str, int, str]],
    sections: List[Tuple[str, str]],
) -> TestReport:
    return TestReport(
        nodeid="tests/x.py::test_x",
        location=("tests/x.py", 1, "test_x"),
        keywords={},
        outcome=outcome,
        longrepr=longrepr,
        when="call",
        sections=sections,
    )


def test_a_failed_reports_longrepr_and_sections_are_redacted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed report's text and its captured sections are redacted in
    place; a skipped report keeps the (path, line, reason) shape pytest's
    summary reads, with the reason redacted; a passed report is left as it
    is, since nothing of it is printed unless a run asks for it, and is
    redacted when the run does (-rP, -rA, junit_logging)."""
    value = "canary-" + secrets.token_hex(16)
    monkeypatch.setenv(CANARY, value)
    failed = _report(
        "failed", f"E   assert {value!r} == ''", [("Captured stdout call", value)]
    )
    skipped = _report("skipped", ("tests/x.py", 1, f"Skipped: {value}"), [])
    passed = _report("passed", None, [("Captured stdout call", value)])
    shown = _report("passed", None, [("Captured stdout call", value)])
    for report in (failed, skipped, passed):
        env_assertions.redact_environment_values(report)
    env_assertions.redact_environment_values(shown, passed_shown=True)
    assert value not in str(failed.longrepr)
    assert [value in text for _, text in failed.sections] == [False]
    assert isinstance(skipped.longrepr, tuple) and len(skipped.longrepr) == 3
    assert value not in skipped.longrepr[2]
    assert [value in text for _, text in passed.sections] == [True]
    assert [value in text for _, text in shown.sections] == [False]


def test_an_xfail_reason_and_a_recorded_property_are_redacted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An xfail's reason (``wasxfail``) reaches the summary and the junit
    report, and a recorded property (``user_properties``) reaches the junit
    report for a passed test too: both are redacted; a property that is not
    text is left."""
    value = "canary-" + secrets.token_hex(16)
    monkeypatch.setenv(CANARY, value)
    report = _report("skipped", ("tests/x.py", 1, "x"), [])
    report.wasxfail = f"reason: {value}"
    env_assertions.redact_environment_values(report)
    passed = TestReport(
        nodeid="tests/x.py::test_x",
        location=("tests/x.py", 1, "test_x"),
        keywords={},
        outcome="passed",
        longrepr=None,
        when="call",
        sections=[],
        user_properties=[("key", value), ("count", 3)],
    )
    env_assertions.redact_environment_values(passed)
    assert value not in report.wasxfail and "<value>" in report.wasxfail
    assert passed.user_properties == [("key", "<value>"), ("count", 3)]


def test_the_live_log_shows_no_environment_value_and_leaves_the_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The live log's formatter redacts a value the environment holds from
    what it shows, and leaves the record, so caplog still gets what was
    logged; a record holding no value is shown as formatted."""
    value = "canary-" + secrets.token_hex(16)
    other = "sentinel-" + secrets.token_hex(16)
    monkeypatch.setenv(CANARY, value)
    formatter = env_assertions.EnvironmentValuesRedacted(
        logging.Formatter("%(message)s")
    )
    holding = logging.LogRecord(
        "probe", logging.WARNING, __file__, 1, "holds %s", (value,), None
    )
    plain = logging.LogRecord(
        "probe", logging.WARNING, __file__, 1, "holds %s", (other,), None
    )
    shown = formatter.format(holding)
    seen = (value in shown, "<value>" in shown, value in holding.getMessage())
    assert seen == (False, True, True)
    assert formatter.format(plain) == f"holds {other}"


def test_the_live_log_redacts_a_value_in_every_form_a_report_does(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The live log shows a line as a report would show it: a value printed
    URL-encoded, JSON-escaped, or cut short where a message shortens it is
    redacted there as redacted_environment_values redacts it from a report."""
    value = "canary-" + secrets.token_hex(16) + ":té"
    monkeypatch.setenv(CANARY, value)
    formatter = env_assertions.EnvironmentValuesRedacted(
        logging.Formatter("%(message)s")
    )
    lines = {
        "URL-encoded": f"GET https://example.invalid/{quote(value, safe='')}",
        "JSON-escaped": "body " + json.dumps({"key": value}),
        "cut short": f"value {value[:24]}... was refused",
    }
    reported = {
        form: env_assertions.redacted_environment_values(line)
        for form, line in lines.items()
    }
    if any(reported[form] == line for form, line in lines.items()):
        raise RuntimeError(("control: a report shows a line as it is", reported))
    shown = {
        form: formatter.format(
            logging.LogRecord("probe", logging.WARNING, __file__, 1, line, None, None)
        )
        for form, line in lines.items()
    }
    assert shown == reported


_FAILURES = """\
import logging
import os
import sys


def test_a_failure_printing_an_environment_value():
    value = os.environ[{canary!r}]
    print("stdout holds", value)
    sys.stderr.write("stderr holds " + value + "\\n")
    logging.getLogger("probe").warning("log holds %s", value)
    short = os.environ[{short!r}]
    raise AssertionError("the failure holds " + value + " beside {sentinel} and " + short)


def test_a_failure_after_its_variable_is_removed(monkeypatch):
    value = os.environ[{removed!r}]
    monkeypatch.delenv({removed!r})
    raise AssertionError("removed " + value)
"""


def _run_under_the_suites_conftest(
    tmp_path: Path,
    source: str,
    environment: Dict[str, str],
    options: Tuple[str, ...] = (),
) -> Tuple[int, str, str]:
    """Run *source* as a test module in a child pytest under the suite's own
    conftest, and give its exit code, its output, and its raw junit report.
    The child's environment is the helper's own plus *environment*: these
    cells assert exact text out of redacted reports, which an inherited host
    value could rewrite."""
    report = tmp_path / "report.xml"
    completed = run_a_child_pytest_under_this_suite(
        source,
        tmp_path,
        prefix="backstop-",
        options=("-rA", *options),
        environment=environment,
        junitxml=report,
    )
    # The junit surface is the raw file: an extraction that read only
    # <failure> elements could never fail on a collection error's <error>,
    # a <skipped> reason, or a <property> name or value.
    junit = report.read_text(encoding="utf-8") if report.exists() else ""
    return completed.returncode, completed.stdout + completed.stderr, junit


def test_a_failing_tests_report_shows_no_environment_value(tmp_path: Path) -> None:
    """Under the suite's conftest, a failing test that prints an environment
    value to stdout, stderr and a log, and fails with it in its message, shows
    it nowhere, in the terminal or the junit report, while text the
    environment does not hold, and a value shorter than MIN_REDACTED_LENGTH,
    are shown; so is a value the session started with after the test removed
    its variable."""
    canary = "canary-" + secrets.token_hex(16)
    removed = "removed-" + secrets.token_hex(16)
    sentinel = "sentinel-" + secrets.token_hex(16)
    returncode, output, junit = _run_under_the_suites_conftest(
        tmp_path,
        _FAILURES.format(
            canary=CANARY, short=SHORT, removed=REMOVED, sentinel=sentinel
        ),
        {CANARY: canary, REMOVED: removed, SHORT: SHORT_VALUE},
    )
    if "2 failed" not in output:
        raise RuntimeError(("control: the probes did not fail", output[-2000:]))
    assert returncode != 0
    printed = {
        "the planted value": canary in output or canary in junit,
        "a removed variable's value": removed in output or removed in junit,
    }
    assert printed == {"the planted value": False, "a removed variable's value": False}
    shown = {
        "text the environment does not hold": sentinel in output and sentinel in junit,
        "a short value": SHORT_VALUE in output,
        # The junit surface is the raw file, where the marker's angle
        # brackets are XML-escaped.
        "the redaction marker": "<value>" in output
        and ("<value>" in junit or "&lt;value&gt;" in junit),
    }
    assert all(shown.values()), shown


_SHORTENED_COMPARISONS = """\
import os
import unittest


class TestShortened(unittest.TestCase):
    def test_a_long_value_cut_by_the_assertion_message(self):
        value = os.environ[{canary!r}]
        self.assertEqual({{"key": value}}, {{"key": "expected"}})
"""


def test_a_cut_values_windows_are_in_no_report_at_default_verbosity(
    tmp_path: Path,
) -> None:
    """unittest's assertEqual shortens each operand's repr around a marker of
    its own, and default verbosity cuts explanations again: no twelve-character
    window of a long environment value survives in the terminal or the junit
    report. The control finds the sentinel's windows, so the search sees."""
    canary = "canary-" + secrets.token_hex(24)
    returncode, output, junit = _run_under_the_suites_conftest(
        tmp_path,
        _SHORTENED_COMPARISONS.format(canary=CANARY),
        {CANARY: canary},
    )
    if "1 failed" not in output:
        raise RuntimeError(("control: the probe did not fail", output[-2000:]))
    assert returncode != 0

    def windows_of(value: str, text: str) -> bool:
        return any(
            value[start : start + 12] in text for start in range(len(value) - 11)
        )

    control = windows_of(canary, f"x {canary[3:30]} y")
    assert control, "the window search finds nothing, so this check is blind"
    assert not windows_of(canary, output), "a window of the value is in the terminal"
    assert not windows_of(canary, junit), "a window of the value is in the junit report"


_LOGGING_AND_PASSING = """\
import logging
import os


def test_a_passing_test_that_logs_an_environment_value():
    logging.getLogger("probe").warning("live log holds %s", os.environ[{canary!r}])
"""


_AN_IMPORT_ERROR_PRINTING_A_VALUE = """\
import os

raise ImportError("cannot import with " + os.environ[{canary!r}])
"""


@pytest.mark.parametrize("workers", ["0", "2"], ids=["one process", "with workers"])
def test_a_collection_errors_text_shows_no_environment_value(
    tmp_path: Path, workers: str
) -> None:
    """A module that fails to collect prints its error in the ERRORS section
    and the junit report through a collect report, not a test report: a
    value the import error's message holds is redacted on both surfaces.
    The junit leg needs the redaction to run before the junit plugin's own
    collect hook, which registers later and so runs first: an <error>
    element was written unredacted while the terminal was already clean."""
    canary = "canary-" + secrets.token_hex(16)
    returncode, output, junit = _run_under_the_suites_conftest(
        tmp_path,
        _AN_IMPORT_ERROR_PRINTING_A_VALUE.format(canary=CANARY),
        {CANARY: canary},
        options=("-n", workers, "-p", "no:randomly"),
    )
    if "cannot import with" not in output or "<error" not in junit:
        raise RuntimeError(("control: the collect error is missing", output[-2000:]))
    assert returncode != 0
    shown = (canary in output, canary in junit, "<value>" in output)
    assert shown == (False, False, True), (
        "a collection error shows an environment value",
        output[-2000:],
        junit[-2000:],
    )


_A_MODULE_LEVEL_SKIP_PRINTING_A_VALUE = """\
import os

import pytest

pytest.skip("skipped with " + os.environ[{canary!r}], allow_module_level=True)
"""


def test_a_module_level_skips_reason_shows_no_environment_value(
    tmp_path: Path,
) -> None:
    """A module-level skip reports its reason through a skipped collect
    report, not a test report: the reason is redacted in the terminal's
    SKIPPED line and the junit <skipped> element, and the skip stays a skip
    (the (path, line, reason) shape is kept)."""
    canary = "canary-" + secrets.token_hex(16)
    returncode, output, junit = _run_under_the_suites_conftest(
        tmp_path,
        _A_MODULE_LEVEL_SKIP_PRINTING_A_VALUE.format(canary=CANARY),
        {CANARY: canary},
    )
    if "skipped with" not in output or "<skipped" not in junit:
        raise RuntimeError(("control: the skip reason is missing", output[-2000:]))
    # The module's only content skipped, so nothing was collected: exit 5.
    assert "1 skipped" in output, output[-2000:]
    shown = (canary in output, canary in junit, "<value>" in output)
    assert shown == (False, False, True), (
        "a module-level skip's reason shows an environment value",
        output[-2000:],
        junit[-2000:],
    )


_A_FAILURE_RECORDING_PROPERTIES = """\
import os


def test_a_failure_recording_properties(record_property, record_testsuite_property):
    value = os.environ[{canary!r}]
    number = os.environ[{number!r}]
    record_property("an-int", int(number))
    record_property("a-list", [value, "beside"])
    record_property("name-holds-" + value, "v")
    record_testsuite_property("suite-holds", "suite holds " + value)
    record_testsuite_property("suite-named-" + value, "sn")
    record_property("sentinel-prop", "SENTINEL-TEXT")
    assert False
"""


def test_recorded_properties_show_no_environment_value_in_any_form(
    tmp_path: Path,
) -> None:
    """The junit report writes each recorded property's name and str(value),
    and a suite-level property goes through the junit plugin's own state,
    never a report: a value inside a non-text property value (an int, a
    list), inside a property NAME, or inside a record_testsuite_property
    value or NAME is redacted all the same. A clean property survives as
    written."""
    canary = "canary-" + secrets.token_hex(16)
    number = str(10**10 + secrets.randbelow(8 * 10**10))
    returncode, output, junit = _run_under_the_suites_conftest(
        tmp_path,
        _A_FAILURE_RECORDING_PROPERTIES.format(canary=CANARY, number=NUMBER_NAME),
        {CANARY: canary, NUMBER_NAME: number},
    )
    if "1 failed" not in output or "SENTINEL-TEXT" not in junit:
        raise RuntimeError(("control: the properties are missing", junit[-2000:]))
    assert returncode != 0
    shown = {
        # The list prints by its repr, so this leg looks for the quoted
        # spelling the repr writes: a bare `canary in junit` was satisfied by
        # ANY leaking leg and pinned none of them.
        "the value in a list property": f"'{canary}'" in junit,
        "the value in a property name": f"name-holds-{canary}" in junit,
        "the numeric value as an int property": number in junit,
        "the value in a suite property": f"suite holds {canary}" in junit,
        "the value in a suite property NAME": f"suite-named-{canary}" in junit,
    }
    assert shown == dict.fromkeys(shown, False), (shown, junit[-2000:])
    assert "suite-holds" in junit, (
        "the suite property was dropped rather than redacted",
        junit[-2000:],
    )


_A_SUITE_PROPERTY_HOLDING_A_CONTROL_CHARACTER = """\
import os


def test_a_passing_test_recording_both_property_kinds(
    record_property, record_testsuite_property
):
    value = os.environ[{canary!r}]
    record_testsuite_property("esc-suite-holder", "esc " + value + " end")
    record_property("esc-case-holder", "esc " + value + " end")
"""


def test_a_suite_property_value_with_an_xml_illegal_character_stays_hidden(
    tmp_path: Path,
) -> None:
    """The junit plugin stores a suite property's value ALREADY ESCAPED
    (add_global_property keeps bin_xml_escape(value)), so a value holding an
    XML-illegal character (ESC here) reaches the end-of-run redaction as
    "#x1B" text that matches no environment value: the redaction has to run
    before the escape. The testcase-level property is the control -- its
    value is redacted on the report, before any escaping, so it was hidden
    all along. The value is kept short so the fragment pass cannot catch
    its halves and hide the gap."""
    canary = "canary-\x1b-" + secrets.token_hex(3)
    escaped = canary.replace("\x1b", "#x1B")
    returncode, output, junit = _run_under_the_suites_conftest(
        tmp_path,
        _A_SUITE_PROPERTY_HOLDING_A_CONTROL_CHARACTER.format(canary=CANARY),
        {CANARY: canary},
    )
    if (
        returncode != 0
        or "esc-suite-holder" not in junit
        or "esc-case-holder" not in junit
    ):
        raise RuntimeError(
            ("control: a property is missing", returncode, junit[-2000:])
        )
    shown = {
        "the value in its escaped storage spelling": escaped in junit,
        "the raw value": canary in junit,
    }
    assert shown == dict.fromkeys(shown, False), (shown, junit[-2000:])


_A_PROPERTY_APPENDED_DIRECTLY = """\
import os


def test_a_property_appended_directly(request):
    from _pytest.junitxml import xml_key

    xml = request.config.stash.get(xml_key, None)
    assert xml is not None, "the junit plugin is not active"
    xml.global_properties.append(
        ("appended-direct", "direct holds " + os.environ[{canary!r}])
    )
    xml.global_properties.append(
        ("appended-named-" + os.environ[{canary!r}], "an")
    )
"""


def test_a_property_appended_directly_to_the_plugins_state_stays_hidden(
    tmp_path: Path,
) -> None:
    """record_testsuite_property is redacted when it is added (the
    sessionstart wrap), so the end-of-run pass over global_properties could
    rot unnoticed: a plugin that APPENDS to the junit plugin's state
    directly bypasses the wrap, and only the end-of-run pass hides what the
    entry holds -- its NAME half included. This cell is that pass's load:
    removing the pass, or its name half, turns it red while every
    record_testsuite_property cell stays green."""
    canary = "canary-" + secrets.token_hex(16)
    returncode, output, junit = _run_under_the_suites_conftest(
        tmp_path,
        _A_PROPERTY_APPENDED_DIRECTLY.format(canary=CANARY),
        {CANARY: canary},
    )
    if returncode != 0 or "appended-direct" not in junit:
        raise RuntimeError(
            ("control: the appended property is missing", returncode, junit[-2000:])
        )
    shown = {
        "the value in a directly appended property": f"direct holds {canary}" in junit,
        "the value in a directly appended NAME": f"appended-named-{canary}" in junit,
        "the raw value anywhere": canary in junit,
    }
    assert shown == dict.fromkeys(shown, False), (shown, junit[-2000:])


_A_WORKER_SET_VALUE_IN_A_REFUSED_WRITE = """\
import os
from pathlib import Path

from tests.utils import real_home_guard

ROOT = Path(os.environ["ASH_TEST_BACKSTOP_PLANT"])
# Known only inside the worker: derived from a hidden value but equal to no
# environment value the parent or the controller holds.
WONLY = "wonly" + os.environ[{canary!r}][::-1].replace("-", "")[:20]
os.environ["ASH_TEST_BACKSTOP_WONLY"] = WONLY
TARGET = ROOT / "vis-a" / WONLY / "planted"


class _Plant:
    def pytest_sessionfinish(self, session):
        with real_home_guard.watching(ROOT):
            try:
                open(TARGET, "w")
            except PermissionError:
                pass


def test_x(request):
    request.config.pluginmanager.register(_Plant(), "backstop-plant")
"""


@pytest.mark.parametrize("workers", ["0", "2"], ids=["one process", "with workers"])
def test_a_value_set_only_in_a_worker_is_hidden_in_the_writes_report(
    tmp_path: Path, workers: str
) -> None:
    """Under xdist the refused-write paths are drained in the WORKER and
    printed by the controller, whose redaction knows only its OWN
    environment's values: a value set only inside a worker has to be
    redacted by the worker before it sends, with the controller's pass as
    the second layer. The one-process run is the control: there the drained
    and printing environments are the same."""
    canary = "canary-" + secrets.token_hex(16)
    wonly = "wonly" + canary[::-1].replace("-", "")[:20]
    if wonly in os.environ.values():
        raise RuntimeError("control: the worker-set value is in this environment")
    plant = tmp_path / "plant-root"
    returncode, output, _ = _run_under_the_suites_conftest(
        tmp_path,
        _A_WORKER_SET_VALUE_IN_A_REFUSED_WRITE.format(canary=CANARY),
        {CANARY: canary, "ASH_TEST_BACKSTOP_PLANT": str(plant)},
        options=("-n", workers, "-p", "no:randomly"),
    )
    lines = [line for line in output.splitlines() if "/vis-a/" in line]
    if (
        "outside any test" not in output
        or len(lines) != 1
        or "/planted" not in lines[0]
    ):
        raise RuntimeError(
            ("control: no single refused-write line", returncode, output[-3000:])
        )
    assert returncode != 0 and not plant.exists(), output[-3000:]
    shown = {
        "the worker-set value": wonly in output,
        # The masked segment itself, not the marker anywhere: the plant root
        # is also an environment value, so a bare marker check could never
        # fail.
        "the worker-set segment masked": "/vis-a/<value>/planted" in lines[0],
    }
    assert shown == {
        "the worker-set value": False,
        "the worker-set segment masked": True,
    }, (workers, shown, lines[0])


_A_PATH_HOLDING_THE_OTHER_WORKERS_VALUE = """\
import hashlib
import os
from pathlib import Path

from tests.utils import real_home_guard

ROOT = Path(os.environ["ASH_TEST_BACKSTOP_PLANT"])
SEED = os.environ[{canary!r}]
WORKER = os.environ.get("PYTEST_XDIST_WORKER", "gwX")


def derived(tag):
    return tag[:5] + hashlib.sha256((tag + SEED).encode("utf-8")).hexdigest()[:20]


OWN = derived("per" + WORKER)
OTHER = derived("per" + ("gw1" if WORKER == "gw0" else "gw0"))
os.environ["ASH_TEST_BACKSTOP_PER"] = OWN
TARGET = ROOT / "vis-a" / OWN / "vis-b" / OTHER / "planted"


class _Plant:
    def pytest_sessionfinish(self, session):
        with real_home_guard.watching(ROOT):
            try:
                open(TARGET, "w")
            except PermissionError:
                pass


def _register(config):
    if not config.pluginmanager.has_plugin("backstop-plant"):
        config.pluginmanager.register(_Plant(), "backstop-plant")


def test_a(request):
    _register(request.config)


def test_b(request):
    _register(request.config)
"""


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason=(
        "the recorded cross-worker limit: a value only another worker holds"
        " is known to neither the writing worker nor the controller"
    ),
)
def test_a_path_holding_the_other_workers_value_hides_it(tmp_path: Path) -> None:
    """Each worker derives its own value and writes a refused path holding
    the OTHER worker's: the writing worker never held it and the controller
    never saw it, so it prints. Recorded as the accepted limit (strict
    xfail); shipping each worker's value set across the execnet channel into
    a reporter that must not raise was weighed and rejected. Each line still
    masks its own worker's value (the control)."""
    import hashlib as hashlib_module

    canary = "canary-" + secrets.token_hex(16)

    def derived(tag: str) -> str:
        return (
            tag[:5]
            + hashlib_module.sha256((tag + canary).encode("utf-8")).hexdigest()[:20]
        )

    plant = tmp_path / "plant-root"
    returncode, output, _ = _run_under_the_suites_conftest(
        tmp_path,
        _A_PATH_HOLDING_THE_OTHER_WORKERS_VALUE.format(canary=CANARY),
        {CANARY: canary, "ASH_TEST_BACKSTOP_PLANT": str(plant)},
        options=("-n", "2", "-p", "no:randomly"),
    )
    lines = [line for line in output.splitlines() if "/vis-a/" in line]
    workers = {line.split(":", 1)[0].strip() for line in lines}
    if returncode == 0 or len(lines) != 2 or workers != {"gw0", "gw1"}:
        raise RuntimeError(
            ("control: not one refused write per worker", returncode, output[-3000:])
        )
    if not all("/vis-a/<value>/vis-b/" in line for line in lines):
        raise RuntimeError(
            ("control: a worker's own value is not hidden", output[-3000:])
        )
    shown = {
        "an other worker's value": derived("pergw0") in output
        or derived("pergw1") in output,
    }
    assert shown == {"an other worker's value": False}, output[-3000:]


_A_WARNING_WITH_A_PATH_ARGUMENT = """\
import os
import pathlib
import warnings


def test_a_warning_holding_a_path():
    value = os.environ[{canary!r}]
    warnings.warn(UserWarning(pathlib.PurePosixPath("/warned/" + value + "/tail")))
"""

_A_WARNING_WHOSE_STR_IGNORES_ARGS = """\
import os
import warnings


class _Carried(UserWarning):
    def __init__(self, value):
        super().__init__("carried")
        self.value = value

    def __str__(self):
        return "carrying " + self.value


def test_a_warning_with_its_own_str():
    warnings.warn(_Carried(os.environ[{canary!r}]))
"""

_A_WARNING_AT_COLLECTION = """\
import os
import warnings

warnings.warn("collected with " + os.environ[{canary!r}])


def test_a_test_after_the_collection_warning():
    pass
"""

_A_WARNING_BUILT_WITH_NO_ARGS = """\
import os
import warnings


class _NoArgs(UserWarning):
    def __init__(self, value):
        super().__init__()
        self.value = value

    def __str__(self):
        return "noargs " + self.value


def test_a_warning_built_with_no_args():
    warnings.warn(_NoArgs(os.environ[{canary!r}]))
"""


@pytest.mark.parametrize(
    "shape, child, control",
    [
        pytest.param(
            "a path argument",
            _A_WARNING_WITH_A_PATH_ARGUMENT,
            "warned",
            id="a path argument",
        ),
        pytest.param(
            "its own __str__",
            _A_WARNING_WHOSE_STR_IGNORES_ARGS,
            "carrying",
            id="its own __str__",
        ),
        pytest.param(
            "warned at collection",
            _A_WARNING_AT_COLLECTION,
            "collected with",
            id="warned at collection",
        ),
        pytest.param(
            "no args at all",
            _A_WARNING_BUILT_WITH_NO_ARGS,
            "noargs",
            id="no args at all",
        ),
    ],
)
def test_the_warnings_summary_shows_no_value_whatever_carries_it(
    tmp_path: Path, shape: str, child: str, control: str
) -> None:
    """The warnings summary prints str(message): a value carried by a
    non-text argument (a path), by a __str__ that ignores the args, by a
    warning raised at collection, or by a warning built with NO args whose
    __str__ carries the value is redacted there like a text argument. (The
    rewritten text arguments alone missed the first two, the collect phase
    records through the same hook, and an early return on empty args let
    the last one print its __str__ unchecked.)"""
    canary = "canary-" + secrets.token_hex(16)
    returncode, output, _ = _run_under_the_suites_conftest(
        tmp_path, child.format(canary=CANARY), {CANARY: canary}
    )
    if returncode != 0 or control not in output:
        raise RuntimeError(
            ("control: the warning is not in the summary", returncode, output[-2000:])
        )
    assert canary not in output, (
        f"the warnings summary shows a value carried by {shape}",
        output[-2000:],
    )


class _StubbornStr(UserWarning):
    """A __str__ that ignores the args: replacing the args alone leaves
    whatever this prints."""

    def __str__(self) -> str:
        return "stubborn text the args do not control"


def test_a_warning_that_cannot_be_redacted_is_replaced_by_the_notice(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The hook's own claim, pinned: a message that cannot be redacted is
    replaced by a notice -- the OBJECT, not only its args, because a __str__
    that ignores the args would still print its own text. The root
    conftest's hook is called directly, with the redaction it imported made
    to raise."""
    import warnings as warnings_module

    import tests.conftest as root_conftest

    def refusing(text: str) -> str:
        raise RuntimeError("probe")

    monkeypatch.setattr(root_conftest, "redacted_environment_values", refusing)
    notice = "this warning could not be redacted, so it is not shown"
    message = warnings_module.WarningMessage(
        _StubbornStr("held text"), _StubbornStr, __file__, 1
    )
    root_conftest.pytest_warning_recorded(
        warning_message=message, when="runtest", nodeid="x", location=None
    )
    assert message.message.args == (notice,)
    assert str(message.message) == notice, (
        "the fallback left a custom __str__ printing its own text",
        str(message.message),
    )


_A_WARNING_PRINTING_A_VALUE = """\
import os
import warnings


def test_a_warning_that_prints_an_environment_value():
    warnings.warn("careful with " + os.environ[{canary!r}])
"""


def test_the_warnings_summary_shows_no_environment_value(tmp_path: Path) -> None:
    """A warning's message is printed by the warnings summary outside every
    test report: a value it holds is redacted there too."""
    canary = "canary-" + secrets.token_hex(16)
    returncode, output, _ = _run_under_the_suites_conftest(
        tmp_path,
        _A_WARNING_PRINTING_A_VALUE.format(canary=CANARY),
        {CANARY: canary},
    )
    if returncode != 0 or "careful with" not in output:
        raise RuntimeError(
            ("control: the warning is not in the summary", returncode, output[-2000:])
        )
    assert canary not in output, (
        "the warnings summary shows an environment value",
        output[-2000:],
    )


_CONTAINMENT_CHILD = """\
import os


def test_the_runs_containment_names_are_kept():
    expected = {expected!r}
    missing = sorted(
        name for name, value in expected.items() if os.environ.get(name) != value
    )
    assert missing == [], missing
"""

#: What a disarmed parent run sets, with benign stand-in values. Both proxy
#: spellings matter: curl and git-over-http prefer the lower-case names for
#: an http:// URL and fall back to all_proxy/ALL_PROXY, so a child missing
#: the lower-case names bypasses a refusing proxy exactly when the parent
#: set no ALL_PROXY either; carrying every spelling closes that case.
#: KRB5CCNAME and SEMGREP_SEND_METRICS point a child off real credentials
#: and telemetry. The AWS file settings are NOT here: the runner pins them
#: to os.devnull instead of copying them (pinned below).
_CONTAINMENT_SET = {
    "GIT_CEILING_DIRECTORIES": "/tmp",
    "HTTP_PROXY": "http://127.0.0.1:9",
    "HTTPS_PROXY": "http://127.0.0.1:9",
    "ALL_PROXY": "http://127.0.0.1:9",
    "NO_PROXY": "localhost",
    "http_proxy": "http://127.0.0.1:9",
    "https_proxy": "http://127.0.0.1:9",
    "all_proxy": "http://127.0.0.1:9",
    "no_proxy": "localhost",
    "AWS_EC2_METADATA_DISABLED": "true",
    "ASH_BIN_PATH": "/tmp/ash-bin-probe",
    "KRB5CCNAME": "/dev/null",
    "SEMGREP_SEND_METRICS": "off",
}


def test_the_childs_environment_keeps_this_runs_containment_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The child runner builds its environment instead of inheriting, but
    every containment name the run sets must survive the build: the ceiling
    keeps a child's git discovery out of shared parents, the proxies in BOTH
    spellings keep curl and git-over-http at the refusing proxy, the
    metadata switch and KRB5CCNAME keep it off real credentials, and
    UV_OFFLINE (set by the runner itself) keeps uv off the network. Their
    values are paths, URLs, or flags, never ordinary words the report
    backstop could rewrite out of asserted text."""
    for name, value in _CONTAINMENT_SET.items():
        monkeypatch.setenv(name, value)
    expected = {**_CONTAINMENT_SET, "UV_OFFLINE": "1"}
    returncode, output, _ = _run_under_the_suites_conftest(
        tmp_path, _CONTAINMENT_CHILD.format(expected=expected), {}
    )
    assert returncode == 0 and "1 passed" in output, (
        "the child lost one of the run's containment names",
        output[-2000:],
    )


_AWS_FILES_CHILD = """\
import os


def test_the_childs_aws_file_settings():
    expected = {expected!r}
    read = {{
        "AWS_CONFIG_FILE": os.environ.get("AWS_CONFIG_FILE"),
        "AWS_SHARED_CREDENTIALS_FILE": os.environ.get(
            "AWS_SHARED_CREDENTIALS_FILE"
        ),
        "AWS_WEB_IDENTITY_TOKEN_FILE": os.environ.get(
            "AWS_WEB_IDENTITY_TOKEN_FILE"
        ),
    }}
    assert read == expected, read
"""


def test_the_childs_aws_file_settings_point_at_devnull_not_the_parents(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The runner pins AWS_CONFIG_FILE and AWS_SHARED_CREDENTIALS_FILE to
    os.devnull and carries no other AWS_*_FILE name. A plain run that points
    them at real files would re-point a child whose scratch HOME was meant
    to hide ~/.aws. A test that needs real AWS files passes them in
    *environment*, which wins over the pins (second run)."""
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "a-real-aws-config"))
    monkeypatch.setenv(
        "AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "real-aws-credentials")
    )
    monkeypatch.setenv("AWS_WEB_IDENTITY_TOKEN_FILE", str(tmp_path / "a-web-token"))
    pinned = {
        "AWS_CONFIG_FILE": os.devnull,
        "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
        "AWS_WEB_IDENTITY_TOKEN_FILE": None,
    }
    (tmp_path / "pinned").mkdir()
    (tmp_path / "explicit").mkdir()
    returncode, output, _ = _run_under_the_suites_conftest(
        tmp_path / "pinned", _AWS_FILES_CHILD.format(expected=pinned), {}
    )
    assert returncode == 0 and "1 passed" in output, (
        "the child read the parent's AWS file settings",
        output[-2000:],
    )
    explicit = {
        "AWS_CONFIG_FILE": str(tmp_path / "an-explicit-config"),
        "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
        "AWS_WEB_IDENTITY_TOKEN_FILE": None,
    }
    returncode, output, _ = _run_under_the_suites_conftest(
        tmp_path / "explicit",
        _AWS_FILES_CHILD.format(expected=explicit),
        {"AWS_CONFIG_FILE": str(tmp_path / "an-explicit-config")},
    )
    assert returncode == 0 and "1 passed" in output, (
        "an explicitly passed AWS file setting did not win over the pin",
        output[-2000:],
    )


_A_PASSING_TEST = """\
def test_nothing():
    pass
"""


def test_the_junit_hostname_attribute_hides_a_value_that_is_the_host_name(
    tmp_path: Path,
) -> None:
    """The junit <testsuite hostname=...> attribute is platform.node(), read
    by the junit plugin while it writes the file, so a variable holding the
    host name (Docker sets HOSTNAME in every container) prints there and
    nowhere else. With such a variable in the child's environment the
    attribute is redacted; without one, the name is kept as written (second
    run), so the redaction cannot hide behind blanking every host name."""
    import platform

    name = platform.node()
    if len(name) < env_assertions.MIN_REDACTED_LENGTH:
        pytest.skip("this host's name is too short for the redaction to apply")
    (tmp_path / "hidden").mkdir()
    (tmp_path / "clean").mkdir()
    returncode, output, junit = _run_under_the_suites_conftest(
        tmp_path / "hidden",
        _A_PASSING_TEST,
        {"ASH_TEST_BACKSTOP_HOSTLIKE": name},
    )
    if returncode != 0 or 'hostname="' not in junit:
        raise RuntimeError(
            ("control: no hostname attribute", returncode, junit[-2000:])
        )
    assert f'hostname="{name}"' not in junit, (
        "the junit hostname attribute shows a value from the set",
        junit[-2000:],
    )
    returncode, output, junit = _run_under_the_suites_conftest(
        tmp_path / "clean", _A_PASSING_TEST, {}
    )
    assert returncode == 0 and f'hostname="{name}"' in junit, (
        "a clean host name was not kept as written",
        junit[-2000:],
    )


def test_the_live_log_shows_no_environment_value(tmp_path: Path) -> None:
    """pytest.ini's log_cli prints each record as it is logged, for a test
    that passes too, outside every report: the live line holds the marker,
    not the value."""
    canary = "canary-" + secrets.token_hex(16)
    returncode, output, _ = _run_under_the_suites_conftest(
        tmp_path, _LOGGING_AND_PASSING.format(canary=CANARY), {CANARY: canary}
    )
    live = [line for line in output.splitlines() if "live log holds" in line]
    if returncode != 0 or not live:
        raise RuntimeError(("control: no live log line", returncode, output[-2000:]))
    assert [canary in line or "<value>" not in line for line in live] == [False] * len(
        live
    )
