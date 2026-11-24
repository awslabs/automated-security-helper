# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The ignore-path decision of the suppression pass, pinned to its Python form.

``apply_suppressions_to_sarif`` decides, for each result, whether its locations
put it under an ignore path: dropped, kept and marked as the client's, or kept
as it is. ``ORACLE`` below is that decision as it was written as inline Python
(``_matching_ignore_path``'s loop and Step 1's counters), kept verbatim. It calls
the same leaf matcher (``ignore_path_matches``) the code calls, so the tests
measure the decision logic and not the glob engine.

The tests were written first against the Python form (the characterization
cases, then the property tests) and have not changed since the decision moved
into ``utils/suppression_frame.py``.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Location,
    Message,
    PhysicalLocation2,
    Region,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils import sarif_utils
from automated_security_helper.utils.sarif_utils import (
    _check_ignore_paths,
    _matching_ignore_path,
    apply_suppressions_to_sarif,
    is_result_suppressed,
)
from automated_security_helper.utils.suppression_matcher import ignore_path_matches

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


# ---------------------------------------------------------------------------
# the oracle: the decision as inline Python
# ---------------------------------------------------------------------------


class ORACLE:
    @staticmethod
    def matching(normalized_uri, ignore_paths):
        for ignore_path in ignore_paths:
            if ignore_path_matches(normalized_uri, ignore_path.path):
                return ignore_path
        return None

    @staticmethod
    def verdict(per_location):
        """``per_location``: for each location that names a file, the ignore path
        it matched or None. Returns ``("drop",)``, ``("client", entry)`` or
        ``("keep",)``."""
        located = 0
        under = 0
        client_ignored = None
        for matched in per_location:
            located += 1
            if matched is not None:
                under += 1
                if getattr(matched, "client_supplied", False) is True:
                    client_ignored = matched
        if located and under == located and client_ignored is None:
            return ("drop",)
        if client_ignored is not None and under < located:
            client_ignored = None
        if client_ignored is not None:
            return ("client", client_ignored)
        return ("keep",)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _context(tmp_path: Path, ignore_paths: list[IgnorePathWithReason]) -> PluginContext:
    source = tmp_path / "src"
    output = source / ".ash" / "ash_output"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True, exist_ok=True)
    config = AshConfig(project_name="w5a")
    config.global_settings.ignore_paths = ignore_paths
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config=config,
    )


def _entry(path: str, client: bool = False) -> IgnorePathWithReason:
    entry = IgnorePathWithReason(path=path, reason=f"reason for {path}")
    if client:
        entry.client_supplied = True
    return entry


def _result(uris: list[str | None], rule: str = "R1") -> Result:
    locations = [
        Location(
            physicalLocation=PhysicalLocation2(
                artifactLocation=ArtifactLocation(uri=uri),
                region=Region(startLine=1, endLine=1),
            )
        )
        for uri in uris
    ]
    return Result(
        ruleId=rule,
        level="error",
        message=Message(text="finding"),
        locations=locations or None,
    )


def _report(results: list[Result]) -> SarifReport:
    return SarifReport(
        version="2.1.0",
        runs=[Run(tool=Tool(driver=ToolComponent(name="scripted")), results=results)],
    )


def _outcome(result: Result, kept: list[Result]) -> tuple:
    if not kept:
        return ("drop",)
    if is_result_suppressed(kept[0]):
        return ("client", tuple(s.justification for s in kept[0].suppressions or []))
    return ("keep",)


# ---------------------------------------------------------------------------
# characterization: the decision on named cases
# ---------------------------------------------------------------------------


def test_matching_ignore_path_is_the_first_entry_that_matches():
    paths = [_entry("docs/"), _entry("*.md"), _entry("vendor/")]
    assert _matching_ignore_path("vendor/a.py", paths) is paths[2]
    assert _matching_ignore_path("docs/x.md", paths) is paths[0]
    assert _matching_ignore_path("x.md", paths) is paths[1]
    assert _matching_ignore_path("src/a.py", paths) is None
    assert _matching_ignore_path("src/a.py", []) is None


def test_check_ignore_paths_returns_the_reason_or_none():
    paths = [_entry("vendor/")]
    assert _check_ignore_paths("vendor/a.py", paths) == "reason for vendor/"
    assert _check_ignore_paths("a.py", paths) is None


def test_matching_ignore_path_stops_at_the_first_match(monkeypatch):
    seen: list[str] = []

    def spy(file_path, pattern):
        seen.append(pattern)
        return pattern == "b"

    monkeypatch.setattr(sarif_utils, "ignore_path_matches", spy)
    paths = [_entry("a"), _entry("b"), _entry("c")]
    assert _matching_ignore_path("x", paths) is paths[1]
    assert seen == ["a", "b"]


def test_matching_ignore_path_calls_every_entry_when_none_matches(monkeypatch):
    seen: list[str] = []
    monkeypatch.setattr(
        sarif_utils,
        "ignore_path_matches",
        lambda file_path, pattern: seen.append(pattern) or False,
    )
    assert _matching_ignore_path("x", [_entry("a"), _entry("b")]) is None
    assert seen == ["a", "b"]


@pytest.mark.parametrize(
    "uris,ignore_paths,expected",
    [
        (["vendor/a.py"], [("vendor/", False)], "drop"),
        (["src/a.py", "vendor/b.py"], [("vendor/", False)], "keep"),
        (["vendor/a.py", "vendor/b.py"], [("vendor/", False)], "drop"),
        (["vendor/a.py"], [("vendor/", True)], "client"),
        (["src/a.py", "vendor/b.py"], [("vendor/", True)], "keep"),
        (["vendor/a.py", "gen/b.py"], [("vendor/", True), ("gen/", False)], "client"),
        (["vendor/a.py", "gen/b.py"], [("vendor/", False), ("gen/", True)], "client"),
        (["vendor/a.py", "gen/b.py"], [("vendor/", True), ("gen/", True)], "client"),
        ([], [("vendor/", False)], "keep"),
        ([None], [("vendor/", False)], "keep"),
        (["", "vendor/a.py"], [("vendor/", False)], "drop"),
        (["my%20app/a.py"], [("my%20app/", False)], "drop"),
        (["my%20app/a.py"], [("my app/", False)], "drop"),
    ],
)
def test_the_decision_for_a_result(tmp_path, uris, ignore_paths, expected):
    entries = [_entry(p, c) for p, c in ignore_paths]
    context = _context(tmp_path, entries)
    result = _result(uris)
    report = apply_suppressions_to_sarif(_report([result]), context)
    kept = report.runs[0].results
    assert _outcome(result, kept)[0] == expected


def test_a_client_supplied_match_records_the_last_matching_entry(tmp_path):
    entries = [_entry("vendor/", True), _entry("gen/", True)]
    context = _context(tmp_path, entries)
    result = _result(["vendor/a.py", "gen/b.py"])
    report = apply_suppressions_to_sarif(_report([result]), context)
    kept = report.runs[0].results[0]
    assert [s.justification for s in kept.suppressions] == [
        "(ASH, client-supplied config) Ignoring finding under ignore path "
        "'gen/' with reason: reason for gen/"
    ]


def test_ignore_suppressions_lifts_the_ignore_paths(tmp_path):
    context = _context(tmp_path, [_entry("vendor/")])
    context.ignore_suppressions = True
    result = _result(["vendor/a.py"])
    report = apply_suppressions_to_sarif(_report([result]), context)
    assert len(report.runs[0].results) == 1


# ---------------------------------------------------------------------------
# properties: the decision against the oracle
# ---------------------------------------------------------------------------

_SEGMENTS = st.sampled_from(
    ["vendor", "src", "gen", "docs", "a", "b", "my%20app", "my app", "[x]", "é"]
)
_FILES = st.sampled_from(["a.py", "b.md", "x.txt", "c.tsx", "[id].tsx", ""])
_URIS = st.builds(
    lambda dirs, name: "/".join([*dirs, name]).strip("/"),
    st.lists(_SEGMENTS, max_size=3),
    _FILES,
)
_PATTERNS = st.one_of(
    st.sampled_from(
        [
            "vendor/",
            "gen/",
            "docs/",
            "*.md",
            "**/gen/**",
            "src/*.py",
            "a.py",
            "my%20app/",
            "my app/",
            "[x]/",
            "",
            ".",
            "**",
            "?",
        ]
    ),
    st.builds(lambda d, f: f"{d}/{f}", _SEGMENTS, _FILES),
)
_ENTRIES = st.builds(_entry, _PATTERNS, st.booleans())


@settings(
    max_examples=400,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(uri=_URIS, entries=st.lists(_ENTRIES, max_size=6))
def test_the_first_match_is_the_oracles(uri, entries):
    assert _matching_ignore_path(uri, entries) is ORACLE.matching(uri, entries)
    reason = _check_ignore_paths(uri, entries)
    expected = ORACLE.matching(uri, entries)
    assert reason == (expected.reason if expected is not None else None)


@settings(
    max_examples=300,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(
    locations=st.lists(st.one_of(st.none(), _URIS), max_size=4),
    entries=st.lists(_ENTRIES, max_size=5),
    ignore_suppressions=st.booleans(),
)
def test_the_decision_for_a_result_is_the_oracles(
    tmp_path_factory, locations, entries, ignore_suppressions
):
    tmp_path = tmp_path_factory.mktemp("w5a")
    context = _context(tmp_path, entries)
    context.ignore_suppressions = ignore_suppressions
    result = _result(locations)
    report = apply_suppressions_to_sarif(_report([result]), context)
    kept = report.runs[0].results

    per_location = []
    for uri in locations:
        if not uri:
            continue
        decoded = sarif_utils._normalize_sarif_uri(
            uri,
            *_prefixes(context),
        )
        matched = None if ignore_suppressions else ORACLE.matching(decoded, entries)
        if matched is None and not ignore_suppressions and "%" in uri:
            as_written = sarif_utils._second_match_spelling(
                uri,
                decoded,
                sarif_utils._normalize_sarif_uri(uri, *_prefixes(context), decode=False),
                _prefixes(context)[0],
            )
            if as_written is not None:
                matched = ORACLE.matching(as_written, entries)
        per_location.append(matched)
    verdict = ORACLE.verdict(per_location)

    if verdict[0] == "drop":
        assert kept == []
    elif verdict[0] == "client":
        assert len(kept) == 1
        assert [s.justification for s in kept[0].suppressions] == [
            "(ASH, client-supplied config) Ignoring finding under "
            f"ignore path '{verdict[1].path}' with reason: {verdict[1].reason}"
        ]
    else:
        assert len(kept) == 1
        assert not is_result_suppressed(kept[0])


def _prefixes(context: PluginContext):
    exclusion = sarif_utils._OutputDirExclusion(context)
    return (
        exclusion.source_dir_prefix,
        exclusion.source_dir_prefix_with_slash,
        exclusion.source_dir_prefix_no_drive,
        exclusion.source_dir_basename,
    )
