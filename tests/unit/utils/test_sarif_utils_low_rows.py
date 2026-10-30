# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Readings of a SARIF report in ``sarif_utils`` that were wrong at the edges.

``get_finding_id`` dropped every None from its seed, so two distinct findings
shared an id. ``file://`` URIs lost a ``#`` in a name and the drive of
``file://C:/p``; only that literal spelling is a file URI, as the matchers read
it. The resolve fallback renamed a file reached through a link inside the tree.
``sanitize_sarif_paths`` left code flows, stacks, fixes and run artifacts absolute.
``attach_scanner_details`` replaced the details a scanner attached. The severity
normalizer read the driver's rules alone, never checked an indexed rule's id, and
graded non-fail results; the metrics raised on a None report. A rejected scanner
suppression blocked ASH's own; an inline comment at every location appended one
suppression each; a symlinked work directory was read as another tree; a drive
letter was compared case-sensitively; the output exclusion ignored the context's
work directory and rewrote a POSIX backslash in the source prefix; and a result
was dropped when any one of its locations matched an ignore path.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.core import AshSuppression, IgnorePathWithReason
from automated_security_helper.schemas.sarif_schema_model import (
    Artifact,
    ArtifactChange,
    ArtifactLocation,
    CodeFlow,
    Fix,
    Kind1,
    Location,
    Message,
    PhysicalLocation2,
    PropertyBag,
    Region,
    Replacement,
    ReportingDescriptor,
    Result,
    Run,
    SarifReport,
    Stack,
    StackFrame,
    State,
    Suppression,
    ThreadFlow,
    ThreadFlowLocation,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils import sarif_utils
from automated_security_helper.utils.sarif_utils import (
    _apply_inline_suppression,
    _file_uri_to_path_text,
    _is_file_uri,
    _normalize_sarif_uri,
    _OutputDirExclusion,
    _sanitize_uri,
    apply_suppressions_to_sarif,
    attach_scanner_details,
    get_finding_id,
    get_severity_metrics_from_sarif,
    is_result_suppressed,
    normalize_sarif_result_severities,
    sanitize_sarif_paths,
)
from automated_security_helper.utils.suppression_matcher import InlineSuppression
from automated_security_helper.utils.undecodable_text import path_in_record_form

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="symlinks and backslash names need POSIX"
)


def _location(uri: str, line: int = 3) -> Location:
    return Location(
        physicalLocation=PhysicalLocation2(
            artifactLocation=ArtifactLocation(uri=uri),
            region=Region(startLine=line, endLine=line),
        )
    )


def _result(uri: str | None = "app.py", **overrides) -> Result:
    values = {
        "ruleId": "RULE-1",
        "level": "error",
        "message": Message(text="finding"),
    }
    if uri is not None:
        values["locations"] = [_location(uri)]
    values.update(overrides)
    return Result(**values)


def _report(*results: Result, **run_extra) -> SarifReport:
    return SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="scripted")),
                results=list(results),
                **run_extra,
            )
        ],
    )


def _context(tmp_path: Path, config: AshConfig | None = None, **extra) -> PluginContext:
    source = tmp_path / "src"
    output = source / ".ash" / "ash_output"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True, exist_ok=True)
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=extra.pop("work_dir", output / ASH_WORK_DIR_NAME),
        config=config or AshConfig(project_name="u28"),
        **extra,
    )


def _ignore_config(path: str = "vendor/") -> AshConfig:
    return AshConfig(
        project_name="u28",
        global_settings={
            "ignore_paths": [IgnorePathWithReason(path=path, reason="third party")]
        },
    )


class TestFindingId:
    def test_a_none_inside_the_seed_keeps_its_position(self):
        # Both read "r::f::1" before.
        assert get_finding_id("r", "f", 1, None) != get_finding_id("r", "f", None, 1)
        assert get_finding_id("r", None, 1, 2) != get_finding_id("r", "1", 2, None)

    def test_the_common_seeds_are_unchanged(self):
        """The ids the pre-fix implementation gave, as exact values.

        Suppression bookkeeping, GHAS fingerprints and baselines carry these ids,
        so the fix (only trailing Nones dropped from the seed) had to keep every
        seed with no inner None byte-identical. The pre-fix seed for these inputs
        was ``"::".join(str(item) for item in parts if item is not None)``, i.e.
        ``r::f::1::2``, ``r::f::1`` and ``r::f``, the same strings the fix
        produces; the values below are the ids of those seed strings (a
        ``random.Random`` seeded with a str is deterministic across Python
        versions), so a change to the seed spelling or the derivation turns
        this red.
        """
        assert get_finding_id("r", "f", 1, 2) == "c86d862b-9d1f-4f7b-a891-b3874444496b"
        assert get_finding_id("r", "f", 1) == "8d7819da-50c3-4b8f-8689-e6bfdb5ddf78"
        assert get_finding_id("r", "f") == "05a9d7f6-d962-4984-b5e3-c7321b4947db"
        # The trailing-None spellings of the same seeds.
        assert get_finding_id("r", "f", 1, None) == get_finding_id("r", "f", 1)
        assert get_finding_id("r", "f", None, None) == get_finding_id("r", "f")

    def test_a_none_field_is_not_the_text_none_but_is_an_empty_field(self):
        """An inner None is an EMPTY field in the seed (``r::::1``), so it differs
        from the file literally named ``None`` (``r::None::1``) and equals a file
        given as the empty string: both say "no file". Pinned as the bytes read;
        whether ``""`` and None should differ is a design row, not this test's."""
        assert get_finding_id("r", None, 1) != get_finding_id("r", "None", 1)
        assert get_finding_id("r", None, 1) == get_finding_id("r", "", 1)
        assert get_finding_id("r", None, 1) == "4aafb9e9-bce1-4896-bac0-b358925da635"


class TestFileUris:
    def test_a_hash_or_question_mark_in_a_name_is_kept(self):
        # urlparse cut the name at the fragment or the query.
        assert _file_uri_to_path_text("file:///srv/a#b.py") == "/srv/a#b.py"
        assert _file_uri_to_path_text("file:///srv/a?b.py") == "/srv/a?b.py"

    def test_the_two_slash_windows_form_keeps_its_drive(self):
        assert _file_uri_to_path_text("file://C:/proj/a.py") == "C:/proj/a.py"
        # A host is still dropped.
        assert _file_uri_to_path_text("file://host/proj/a.py") == "/proj/a.py"

    def test_a_posix_path_whose_third_character_is_a_colon_keeps_its_slash(self):
        # Only a letter before the colon is a drive; "1:" is a POSIX name.
        assert _file_uri_to_path_text("file:///1:/file.py") == "/1:/file.py"
        assert _file_uri_to_path_text("file:///C:/file.py") == "C:/file.py"
        # A lower-case drive letter is a drive too.
        assert _file_uri_to_path_text("file:///c:/file.py") == "c:/file.py"

    def test_an_encoded_hash_decodes_where_a_raw_one_is_kept(self):
        """``%23`` is a percent-encoded ``#`` and decodes to one; the raw ``#``
        of the test above is kept because the URI is cut on its own slashes, not
        parsed. Both name the file ``/srv/a#b.py``."""
        assert _file_uri_to_path_text("file:///srv/a%23b.py") == "/srv/a#b.py"
        assert _file_uri_to_path_text("file:///srv/a%3Fb.py") == "/srv/a?b.py"

    def test_an_encoded_drive_colon_is_not_folded_as_a_drive(self):
        """VS Code spells a Windows file URI ``file:///c%3A/x``. The drive test
        runs before the percent-decode and reads the third character, ``%``, so
        this spelling keeps its leading slash: ``/c:/x``, the form pathlib calls
        neither absolute nor drive-bearing. Pinned as the bytes read; folding the
        encoded colon too is a design row, not this test's."""
        assert _file_uri_to_path_text("file:///c%3A/x/a.py") == "/c:/x/a.py"

    def test_only_the_literal_two_slash_scheme_is_a_file_uri(self):
        """The matchers read exactly ``file://``; the other spellings stay as
        written so a location and its pattern are spelled alike on both sides.

        KNOWN LIMITATION, kept by design: the one-slash form ``file:/abs/path``
        is a valid file URI (RFC 8089 section 2 admits the minimal
        ``file:/path`` form, and Java's ``File.toURI()`` writes it) but is not
        read as one here, so a scanner that writes it keeps the scheme in its
        location text and a pattern against the bare path does not meet it.
        No scanner ASH runs is known to write that form; widening the test would
        change every matcher's reading at once, so it stays a row rather than a
        cut, and this test pins the narrowing as the bytes read."""
        assert _is_file_uri("file:///abs/path")
        assert _is_file_uri("file://C:/abs/path")
        assert not _is_file_uri("file:/abs/path")
        assert not _is_file_uri("FILE:///abs/path")
        assert not _is_file_uri("files/a.py")


@posix_only
def test_a_link_inside_the_tree_keeps_its_name_when_the_root_is_respelled(tmp_path):
    source = tmp_path / "repo"
    (source / "real").mkdir(parents=True)
    (source / "real" / "f.py").write_text("x = 1\n", encoding="utf-8")
    os.symlink(source / "real", source / "link", target_is_directory=True)
    # Another spelling of the source directory, as macOS gives /tmp for /private/tmp.
    alias = tmp_path / "alias"
    os.symlink(source, alias, target_is_directory=True)
    resolved = path_in_record_form(source.resolve())

    uri = _sanitize_uri(
        f"{alias.as_posix()}/link/f.py", resolved, resolved.as_posix() + "/"
    )

    # The whole URI was resolved, so the finding was recorded under real/f.py.
    assert uri == "link/f.py"


def test_code_flows_stacks_fixes_and_artifacts_are_made_relative(tmp_path):
    source = tmp_path / "repo"
    source.mkdir()
    absolute = f"{source.resolve().as_posix()}/src/a.py"
    result = _result(
        absolute,
        codeFlows=[
            CodeFlow(
                threadFlows=[
                    ThreadFlow(
                        locations=[ThreadFlowLocation(location=_location(absolute))]
                    )
                ]
            )
        ],
        stacks=[Stack(frames=[StackFrame(location=_location(absolute))])],
        fixes=[
            Fix(
                artifactChanges=[
                    ArtifactChange(
                        artifactLocation=ArtifactLocation(uri=absolute),
                        replacements=[Replacement(deletedRegion=Region(startLine=1))],
                    )
                ]
            )
        ],
    )
    report = _report(
        result, artifacts=[Artifact(location=ArtifactLocation(uri=absolute))]
    )

    sanitize_sarif_paths(report, source)

    run = report.runs[0]
    kept = run.results[0]
    flow_location = kept.codeFlows[0].threadFlows[0].locations[0].location
    assert flow_location.physicalLocation.root.artifactLocation.uri == "src/a.py"
    frame_location = kept.stacks[0].frames[0].location
    assert frame_location.physicalLocation.root.artifactLocation.uri == "src/a.py"
    assert kept.fixes[0].artifactChanges[0].artifactLocation.uri == "src/a.py"
    assert run.artifacts[0].location.uri == "src/a.py"
    assert kept.locations[0].physicalLocation.root.artifactLocation.uri == "src/a.py"


def test_attach_scanner_details_keeps_what_the_scanner_attached():
    result = _result(properties=PropertyBag())
    result.properties.scanner_details = {
        "tool_name": "bandit",
        "tool_invocation": {"command_line": "bandit -r .", "exit_code": 1},
    }
    report = _report(result)

    attach_scanner_details(report, "bandit", "1.7")

    details = report.runs[0].results[0].properties.scanner_details
    # Replaced whole before, so the command line and exit code were gone.
    assert details["tool_invocation"] == {"command_line": "bandit -r .", "exit_code": 1}
    assert details["tool_version"] == "1.7"


def test_attach_scanner_details_lets_the_call_win_a_conflicting_key():
    """The merge is ``{**existing, **scanner_details}``: a key both sides carry
    takes the value of this call, and a key only the scanner attached is kept.
    So a scanner that wrote ``tool_version: "unknown"`` is corrected by the
    version ASH passes, while its ``tool_invocation`` and any extra key survive.
    The run-level ``tool.driver.properties.scanner_details`` is still replaced
    whole; only the per-result object is merged."""
    result = _result(properties=PropertyBag())
    result.properties.scanner_details = {
        "tool_name": "bandit",
        "tool_version": "unknown",
        "tool_invocation": {"command_line": "bandit -r ."},
        "extra": "kept",
    }
    report = _report(result)

    attach_scanner_details(report, "bandit", "1.7")

    details = report.runs[0].results[0].properties.scanner_details
    assert details["tool_version"] == "1.7"
    assert details["tool_invocation"] == {"command_line": "bandit -r ."}
    assert details["extra"] == "kept"
    assert report.runs[0].tool.driver.properties.scanner_details == {
        "tool_name": "bandit",
        "tool_version": "1.7",
    }


class TestSeverityNormalization:
    def _run(self, result: Result, driver_rules, extension_rules=None) -> SarifReport:
        return SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(
                        driver=ToolComponent(name="ash", rules=driver_rules),
                        extensions=[ToolComponent(name="grype", rules=extension_rules)]
                        if extension_rules is not None
                        else None,
                    ),
                    results=[result],
                )
            ],
        )

    @staticmethod
    def _rule(rule_id: str, score: str) -> ReportingDescriptor:
        return ReportingDescriptor(
            id=rule_id, properties=PropertyBag(**{"security-severity": score})
        )

    def test_a_rule_in_an_extension_is_found_through_the_rule_reference(self):
        result = _result(
            ruleId="CVE-1",
            ruleIndex=0,
            rule={"id": "CVE-1", "index": 0, "toolComponent": {"index": 0}},
        )
        report = self._run(
            result, [self._rule("OTHER", "2.0")], [self._rule("CVE-1", "9.5")]
        )

        normalize_sarif_result_severities(report)

        # ruleIndex 0 into the driver's rules gave OTHER's LOW before.
        assert report.runs[0].results[0].properties.issue_severity == "CRITICAL"

    def test_an_indexed_rule_whose_id_disagrees_is_looked_up_by_id(self):
        result = _result(ruleId="B", ruleIndex=0)
        report = self._run(result, [self._rule("A", "2.0"), self._rule("B", "9.0")])

        normalize_sarif_result_severities(report)

        assert report.runs[0].results[0].properties.issue_severity == "CRITICAL"

    def test_a_result_that_is_not_a_fail_is_not_graded(self):
        # SARIF 3.27.10: a result whose kind is not fail carries level "none";
        # the fixture's default "error" is not a valid pairing.
        result = _result(kind="pass", level="none", ruleId="A")
        report = self._run(result, [self._rule("A", "9.8")])

        normalize_sarif_result_severities(report)

        graded = report.runs[0].results[0]
        assert getattr(graded.properties, "issue_severity", None) is None
        # The normalizer created no property bag for it either.
        assert graded.properties is None

    def test_the_metrics_of_no_report_are_zero_not_an_error(self):
        counts = get_severity_metrics_from_sarif(None, MagicMock())

        assert counts.critical == 0 and counts.suppressed == 0


def test_a_rejected_scanner_suppression_does_not_block_a_config_one(tmp_path):
    config = AshConfig(
        project_name="u28",
        global_settings={
            "suppressions": [
                AshSuppression(rule_id="RULE-1", path="app.py", reason="x")
            ]
        },
    )
    result = _result(
        suppressions=[Suppression(kind=Kind1.inSource, state=State.rejected)]
    )

    report = apply_suppressions_to_sarif(_report(result), _context(tmp_path, config))

    kept = report.runs[0].results[0]
    # The rejected one counted as "already suppressed" and the entry never applied.
    assert is_result_suppressed(kept) is True
    assert any("(ASH)" in (s.justification or "") for s in kept.suppressions)


def test_an_inline_comment_at_every_location_appends_one_suppression(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(
        sarif_utils,
        "find_inline_suppressions",
        lambda file_path, scan_root=None: [
            InlineSuppression(line_number=3, rule_id="RULE-1", reason="noted")
        ],
    )
    result = _result(locations=[_location("a.py"), _location("b.py")])

    report = apply_suppressions_to_sarif(_report(result), _context(tmp_path))

    # Appended one per location before.
    assert len(report.runs[0].results[0].suppressions) == 1


@posix_only
def test_a_symlinked_work_directory_is_the_scan_root_of_its_files(
    tmp_path, monkeypatch
):
    context = _context(tmp_path)
    converted = context.work_dir / "conv.py"
    converted.write_text("x = 1\n", encoding="utf-8")
    link = tmp_path / "outlink"
    os.symlink(context.output_dir, link, target_is_directory=True)
    seen = {}

    def _capture(file_path, scan_root=None):
        seen["scan_root"] = scan_root
        return []

    monkeypatch.setattr(sarif_utils, "find_inline_suppressions", _capture)

    _apply_inline_suppression(
        result=_result(),
        normalized_uri=str(converted.resolve()),
        source_dir=context.source_dir,
        result_line=3,
        inline_cache={},
        work_dir=link / ASH_WORK_DIR_NAME,
    )

    # The two spellings compared as text, so the file read against the source
    # tree. The scan root is the work directory whichever spelling the read
    # chose, so both sides are resolved before comparing.
    assert seen["scan_root"] is not None
    assert Path(seen["scan_root"]).resolve() == (link / ASH_WORK_DIR_NAME).resolve()


def test_a_drive_letter_prefix_is_compared_without_regard_to_case():
    assert _normalize_sarif_uri(
        "c:/Repo/src/a.py", "C:/Repo/", "/C:/Repo/", "/Repo/", None
    ) == ("src/a.py")
    assert _normalize_sarif_uri(
        "/c:/Repo/src/a.py", "C:/Repo/", "/C:/Repo/", "/Repo/", None
    ) == ("src/a.py")


def test_the_exclusion_reads_the_contexts_work_directory(tmp_path):
    source = tmp_path / "src"
    output = source / ".ash" / "ash_output"
    elsewhere = output / "converted-here"
    elsewhere.mkdir(parents=True)
    (elsewhere / "conv.py").write_text("x = 1\n", encoding="utf-8")
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=elsewhere,
        config=AshConfig(project_name="u28"),
    )

    exclusion = _OutputDirExclusion(context)

    assert exclusion.work_dir == elsewhere.resolve()
    # A converted-file finding there was excluded as ASH's own output.
    assert exclusion.holds(".ash/ash_output/converted-here/conv.py") is False
    assert exclusion.holds(".ash/ash_output/reports/ash.html") is True


@posix_only
def test_a_backslash_in_a_posix_source_directory_name_is_kept_in_the_prefix(tmp_path):
    source = tmp_path / "a\\b"
    output = source / ".ash" / "ash_output"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True)
    context = PluginContext(
        source_dir=source, output_dir=output, config=AshConfig(project_name="u28")
    )

    exclusion = _OutputDirExclusion(context)

    # The bare replace spelled it a/b/, which no URI under it starts with.
    assert exclusion.source_dir_prefix.endswith("/a\\b/")
    assert exclusion.normalize(f"{source.resolve().as_posix()}/src/x.py") == "src/x.py"


def test_ignore_suppressions_lifts_the_ignore_paths_too(tmp_path):
    context = _context(tmp_path, _ignore_config(), ignore_suppressions=True)

    report = apply_suppressions_to_sarif(_report(_result("vendor/a.py")), context)

    # An ignore path is a suppression, so the flag lifts it with the rest: the
    # ignore-path arm of Step 1 reads the flag and matches nothing under it, and
    # the result that the ignore path would have dropped is kept.
    assert [r.ruleId for r in report.runs[0].results] == ["RULE-1"]
    assert not report.runs[0].results[0].suppressions


def test_a_result_is_dropped_only_when_every_location_is_under_an_ignore_path(
    tmp_path,
):
    context = _context(tmp_path, _ignore_config())
    mixed = _result(locations=[_location("src/a.py"), _location("vendor/b.py")])
    mixed.ruleId = "MIXED"
    all_ignored = _result(
        locations=[_location("vendor/a.py"), _location("vendor/b.py")]
    )
    all_ignored.ruleId = "IGNORED"

    report = apply_suppressions_to_sarif(_report(mixed, all_ignored), context)

    # The mixed result was dropped on its one matching location.
    assert [r.ruleId for r in report.runs[0].results] == ["MIXED"]


def test_a_kept_result_keeps_its_ignored_location_in_place(tmp_path):
    """The ignore pass is a filter over results, never an editor of them: the
    location loop counts matches and drops the result only when every located
    entry is under an ignore path. A result kept because one location lies
    outside is passed on with its locations as the scanner wrote them, the
    ignored one first here, so the order and the count are unchanged. Removing
    or reordering would alter the scanner's report and move the primary
    location (the first) that reporters read."""
    context = _context(tmp_path, _ignore_config())
    vendor_first = _result(locations=[_location("vendor/b.py"), _location("src/a.py")])
    vendor_first.ruleId = "VENDOR-FIRST"

    report = apply_suppressions_to_sarif(_report(vendor_first), context)

    kept = report.runs[0].results
    assert [r.ruleId for r in kept] == ["VENDOR-FIRST"]
    assert [
        loc.physicalLocation.root.artifactLocation.uri for loc in kept[0].locations
    ] == ["vendor/b.py", "src/a.py"]
    assert not kept[0].suppressions
