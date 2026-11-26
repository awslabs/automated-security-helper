# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The conformance harness over the fixture plugin: the positive control, then one
planted defect per row (design 4.5, unit A6).

The fixture plugin is the smallest plugin that conforms. Every row of the bar that can be
read without CI is green over it; each planted-defect test breaks exactly one thing in a
private copy and expects exactly the one row that guards it to change, and the rest to
stay as they were (the whole row-status map is compared, by ``_expect``). A row that
cannot go red on a planted defect is documentation.
"""

import json
import subprocess

import pytest
from pydantic import BaseModel

from automated_security_helper.base.plugin_manifest import PluginTier
from automated_security_helper.base.scanner_operational_facets import (
    LICENSE_NOT_READ,
    ProvenanceFacet,
    ProvenanceSource,
)
from automated_security_helper.core.plugin_conformance import (
    EXIT_FAIL,
    EXIT_INCOMPLETE,
    RowStatus,
    discover_transcripts,
    unconfirmed_cells,
    verify_plugin,
)

pytestmark = pytest.mark.unit

PINS: dict[str, str] = {}


def _verify(manifest, root, **kwargs):
    kwargs.setdefault("tool_type", "SAST")
    kwargs.setdefault("pins", PINS)
    return verify_plugin(manifest, root, **kwargs)


def _status(report) -> dict[int, RowStatus]:
    return {row.number: row.status for row in report.rows}


def _row(report, number):
    return next(row for row in report.rows if row.number == number)


GREEN, RED, NOT_RUN = RowStatus.GREEN, RowStatus.RED, RowStatus.NOT_RUN

#: Every row's status over the unharmed fixture plugin with no CI result supplied.
CONTROL: dict[int, RowStatus] = {1: GREEN, 2: GREEN, 3: NOT_RUN, 4: GREEN, 5: NOT_RUN}


def _expect(report, **changed: RowStatus) -> None:
    """The whole row-status map is the control's but for the named rows (``r1=RED``)."""
    expected = {**CONTROL, **{int(k.removeprefix("r")): v for k, v in changed.items()}}
    assert _status(report) == expected


# ---- the positive control -------------------------------------------------


def test_the_fixture_plugin_reads_green_on_every_row_that_needs_no_ci(
    fixture_manifest, transcripts_copy
) -> None:
    report = _verify(fixture_manifest, transcripts_copy)
    assert _status(report) == {1: GREEN, 2: GREEN, 3: NOT_RUN, 4: GREEN, 5: NOT_RUN}
    assert report.tier == PluginTier.ALPHA.value
    assert report.verdict == "incomplete" and report.exit_code == EXIT_INCOMPLETE


def test_the_control_is_not_vacuous_it_judges_every_observable_facet(
    fixture_manifest, transcripts_copy
) -> None:
    report = _verify(fixture_manifest, transcripts_copy)
    judged = {v.facet: v for v in report.verdicts}
    assert len(judged) == 20
    assert judged["rule_id"].outcome == "ok" and judged["rule_id"].non_null == 2
    assert judged["file_path"].non_null == 2 and judged["line_range"].non_null == 2
    assert judged["resource_id"].non_null == 0  # declared N/A, observed empty
    assert {v.outcome for v in report.verdicts} == {"ok", "excluded"}


def test_a_live_result_green_on_the_declared_platform_makes_row_three_green(
    fixture_manifest, transcripts_copy
) -> None:
    report = _verify(fixture_manifest, transcripts_copy, live_results={"host": True})
    assert _status(report)[3] is GREEN
    # the docs row still has no generator, so the verdict is incomplete, never pass
    assert report.verdict == "incomplete"


def test_the_report_serializes_for_the_json_output(
    fixture_manifest, transcripts_copy
) -> None:
    document = _verify(fixture_manifest, transcripts_copy).as_dict()
    assert json.loads(json.dumps(document))["verdict"] == "incomplete"
    assert [row["row"] for row in document["rows"]] == [1, 2, 3, 4, 5]
    # the per-cell verdicts behind row 1 travel with it, one per facet
    assert len(document["verdicts"]) == 20
    rule_id = next(v for v in document["verdicts"] if v["facet"] == "rule_id")
    assert rule_id["outcome"] == "ok" and rule_id["non_null"] == 2


def test_the_operational_row_has_one_name_whether_it_is_green_or_red(
    fixture_manifest, transcripts_copy
) -> None:
    from ash_fixture_plugin.scanner import FixtureScanner

    from automated_security_helper.base import scanner_operational_facets as opsf

    green = _row(_verify(fixture_manifest, transcripts_copy), 2)
    original = FixtureScanner.operational_facets
    FixtureScanner.operational_facets = original.model_copy(
        update={
            "identity": opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.UNCONFIRMED,
                note="not read at a fixture yet",
            )
        }
    )
    try:
        red = _row(_verify(fixture_manifest, transcripts_copy), 2)
    finally:
        FixtureScanner.operational_facets = original
    assert green.status is GREEN and red.status is RED
    assert green.name == red.name


def test_a_scanner_with_no_table_entry_gets_its_tool_type_from_its_own_row(
    fixture_manifest, transcripts_copy
) -> None:
    """The CLI never passes a tool type; a scanner outside the shipped table is judged
    on the type its operational row declares instead of raising KeyError."""
    report = verify_plugin(fixture_manifest, transcripts_copy, pins=PINS)
    _expect(report)
    assert {v.outcome for v in report.verdicts} == {"ok", "excluded"}


def test_a_tool_type_declared_nowhere_is_none_not_a_crash() -> None:
    from automated_security_helper.core.plugin_conformance import _tool_type_of

    class Undeclared:
        pass

    assert _tool_type_of("not-a-shipped-scanner", Undeclared, None) is None
    assert _tool_type_of("not-a-shipped-scanner", Undeclared, "SCA") == "SCA"


def test_a_shipped_scanners_tool_type_comes_from_the_table_not_its_own_row() -> None:
    """The parity gates read flat rows through ``observed_frame``, which resolves a
    shipped scanner from ``SCANNER_TOOL_TYPES``; the verify bar resolves through
    ``_tool_type_of``. An operational row that drifts from the table must not make
    the two surfaces read one scanner's rows under two tool types, so for a shipped
    scanner the table wins and the row speaks only outside it."""
    from types import SimpleNamespace

    from automated_security_helper.core.plugin_conformance import _tool_type_of
    from automated_security_helper.utils.scanner_names import SCANNER_TOOL_TYPES

    class Drifted:
        operational_facets = SimpleNamespace(targets=SimpleNamespace(tool_type="IAC"))

    assert SCANNER_TOOL_TYPES["bandit"] == "SAST"
    assert _tool_type_of("bandit", Drifted, None) == "SAST"
    # outside the shipped table the operational row still speaks
    assert _tool_type_of("not-a-shipped-scanner", Drifted, None) == "IAC"
    # and the caller's override outranks both
    assert _tool_type_of("bandit", Drifted, "SCA") == "SCA"


# ---- row 1: facets over committed transcripts ------------------------------


def test_planted_an_edited_results_file_turns_row_one_red(
    fixture_manifest, transcripts_copy
) -> None:
    sarif = next(transcripts_copy.rglob("fixture-lint-1.0.0.sarif"))
    sarif.write_text(sarif.read_text().replace("FX001", "FX999"), encoding="utf-8")
    report = _verify(fixture_manifest, transcripts_copy)
    _expect(report, r1=RED)
    assert "no longer matches the digest" in " ".join(_row(report, 1).details)
    assert report.exit_code == EXIT_FAIL


def test_planted_a_removed_transcript_turns_row_one_red_naming_the_scanner(
    fixture_manifest, transcripts_copy
) -> None:
    next(transcripts_copy.rglob("transcripts.json")).unlink()
    report = _verify(fixture_manifest, transcripts_copy)
    _expect(report, r1=RED)
    # one finding: no per-facet failures piled on top of it
    assert len(_row(report, 1).details) == 1
    assert "fixture-lint has no recorded transcript" in _row(report, 1).details[0]


# ---- row 1: a damaged recording is a red row, never a traceback -------------


def test_planted_a_deleted_results_file_is_a_red_row_not_a_traceback(
    fixture_manifest, transcripts_copy
) -> None:
    next(transcripts_copy.rglob("fixture-lint-1.0.0.sarif")).unlink()
    report = _verify(fixture_manifest, transcripts_copy)
    _expect(report, r1=RED)
    details = " ".join(_row(report, 1).details)
    assert "captured/fixture-lint-1.0.0.sarif is not a file" in details
    # the recording failed its digest, so it is not what the facets are judged over
    assert report.verdicts == ()


def test_planted_a_truncated_results_file_is_a_red_row_not_a_traceback(
    fixture_manifest, transcripts_copy
) -> None:
    sarif = next(transcripts_copy.rglob("fixture-lint-1.0.0.sarif"))
    text = sarif.read_text(encoding="utf-8")
    sarif.write_text(text[: len(text) // 2], encoding="utf-8")
    report = _verify(fixture_manifest, transcripts_copy)
    _expect(report, r1=RED)
    assert "no longer matches the digest" in " ".join(_row(report, 1).details)
    assert report.verdicts == ()


@pytest.mark.parametrize(
    "bytes_on_disk",
    ["{ this is not json", '{"version": "2.1.0", "runs": "not a list"}'],
    ids=["invalid-json", "invalid-sarif"],
)
def test_planted_a_results_file_whose_digest_matches_but_cannot_be_read_is_red(
    fixture_manifest, transcripts_copy, bytes_on_disk
) -> None:
    """An LFS pointer or a schema-invalid file that was recorded as it is."""
    sarif = next(transcripts_copy.rglob("fixture-lint-1.0.0.sarif"))
    sarif.write_text(bytes_on_disk, encoding="utf-8")
    _restamp_digest(transcripts_copy, sarif)
    report = _verify(fixture_manifest, transcripts_copy)
    _expect(report, r1=RED)
    assert "its results could not be read" in " ".join(_row(report, 1).details)


def test_planted_an_unregistered_adapter_prep_is_a_red_row_naming_it(
    fixture_manifest, transcripts_copy
) -> None:
    path = next(transcripts_copy.rglob("transcripts.json"))
    document = json.loads(path.read_text())
    document["transcripts"][0]["adapter_prep"] = "no-such-prep"
    path.write_text(json.dumps(document), encoding="utf-8")
    report = _verify(fixture_manifest, transcripts_copy)
    _expect(report, r1=RED)
    details = " ".join(_row(report, 1).details)
    assert "'no-such-prep'" in details and "not registered" in details


def _plant_a_foreign_transcript_file(root, text: str) -> None:
    other = root / "other"
    other.mkdir()
    (other / "transcripts.json").write_text(text, encoding="utf-8")


def test_planted_a_foreign_newer_schema_file_does_not_stop_a_healthy_scanner(
    fixture_manifest, transcripts_copy
) -> None:
    _plant_a_foreign_transcript_file(
        transcripts_copy,
        json.dumps(
            {
                "schema_version": 2,
                "transcripts": [{"id": "x-1", "scanner": "other-tool"}],
            }
        ),
    )
    report = _verify(fixture_manifest, transcripts_copy)
    _expect(report)
    found = discover_transcripts(transcripts_copy)
    assert len(found.files) == 1 and len(found.unreadable) == 1
    assert found.unreadable[0].scanners == frozenset({"other-tool"})
    assert "other/transcripts.json" in found.unreadable[0].problem
    assert "upgrade ASH to read it" in found.unreadable[0].problem


def test_planted_a_transcript_file_that_names_no_scanner_is_told_to_every_scanner(
    fixture_manifest, transcripts_copy
) -> None:
    _plant_a_foreign_transcript_file(transcripts_copy, "{ not json")
    report = _verify(fixture_manifest, transcripts_copy)
    _expect(report, r1=RED)
    assert "other/transcripts.json cannot be read as JSON" in " ".join(
        _row(report, 1).details
    )


def test_planted_a_transcripts_key_that_is_not_a_list_is_a_red_row_not_a_traceback(
    fixture_manifest, transcripts_copy
) -> None:
    """The damaged shape the walk exists to survive: ``transcripts: 5`` fails the
    parse, and the scanner-naming read over the damage must not raise either."""
    _plant_a_foreign_transcript_file(
        transcripts_copy,
        json.dumps({"schema_version": 1, "transcripts": 5, "unrecorded": 7}),
    )
    report = _verify(fixture_manifest, transcripts_copy)
    _expect(report, r1=RED)
    details = " ".join(_row(report, 1).details)
    assert "other/transcripts.json is not a transcript file this ASH reads" in details


def test_planted_a_deeply_nested_file_does_not_abort_the_walk(
    fixture_manifest, transcripts_copy
) -> None:
    """One file nested past the interpreter's recursion limit is one damaged file
    (the walk's own contract), never a RecursionError out of the whole discovery.

    The depth is a constant well past any interpreter's limit: 3.14's C decoder
    probes the real stack and parses thousands of levels before it raises, where
    older interpreters raise near ``sys.getrecursionlimit()``."""
    depth = 200_000
    _plant_a_foreign_transcript_file(transcripts_copy, "[" * depth + "]" * depth)
    found = discover_transcripts(transcripts_copy)
    assert len(found.files) == 1 and len(found.unreadable) == 1
    assert "cannot be read as JSON" in found.unreadable[0].problem
    assert "RecursionError" in found.unreadable[0].problem
    report = _verify(fixture_manifest, transcripts_copy)
    _expect(report, r1=RED)


def test_planted_a_damaged_mapping_naming_no_scanner_concerns_every_scanner(
    fixture_manifest, transcripts_copy
) -> None:
    """A parsed-but-refused file with no v1 scanner keys is everyone's problem: an
    empty name set would report it to NO scanner, who would instead read 'has no
    recorded transcript; record one'."""
    _plant_a_foreign_transcript_file(
        transcripts_copy, json.dumps({"schema_version": 1, "transcripts": {}})
    )
    found = discover_transcripts(transcripts_copy)
    assert len(found.unreadable) == 1
    assert found.unreadable[0].scanners is None
    assert found.unreadable[0].concerns("fixture-lint")
    report = _verify(fixture_manifest, transcripts_copy)
    _expect(report, r1=RED)


def test_discovery_once_serves_many_manifests(
    fixture_manifest, transcripts_copy
) -> None:
    found = discover_transcripts(transcripts_copy)
    alone = _verify(fixture_manifest, transcripts_copy)
    shared = _verify(fixture_manifest, transcripts_copy, discovered=found)
    assert shared.as_dict() == alone.as_dict()


def test_planted_a_mapped_cell_only_a_historical_recording_still_fills_fails(
    fixture_manifest, transcripts_copy
) -> None:
    """The current pin stopped filling ``file_path``; an old recording still does.

    Judged over every recording the cell reads "ok" off the old one, and the drift row
    1 exists to catch stays green. Mapped cells are judged over current recordings."""
    import shutil

    sarif = next(transcripts_copy.rglob("fixture-lint-1.0.0.sarif"))
    old = sarif.with_name("fixture-lint-0.9.0.sarif")
    shutil.copyfile(sarif, old)
    document = json.loads(sarif.read_text())
    for result in document["runs"][0]["results"]:
        del result["locations"]
    sarif.write_text(json.dumps(document), encoding="utf-8")
    _restamp_digest(transcripts_copy, sarif)
    path = next(transcripts_copy.rglob("transcripts.json"))
    data = json.loads(path.read_text())
    historical = json.loads(json.dumps(data["transcripts"][0]))
    from automated_security_helper.base.tool_transcript import file_sha256

    historical.update(
        id="fixture-lint-0.9.0-app",
        retention="historical",
        reason="the previous release's output shape",
        tool={"name": "fixture-lint", "version": "0.9.0"},
        results=[
            {
                "format": "sarif",
                "path": "captured/fixture-lint-0.9.0.sarif",
                "sha256": file_sha256(old),
            }
        ],
    )
    data["transcripts"].append(historical)
    path.write_text(json.dumps(data), encoding="utf-8")
    report = _verify(fixture_manifest, transcripts_copy)
    _expect(report, r1=RED)
    details = " ".join(_row(report, 1).details)
    assert "fixture-lint.file_path declared mapped" in details
    assert "fixture-lint.line_range declared mapped" in details
    # and a N/A cell is still judged over every recording
    assert "declared n/a" not in details


def _plant_a_historical_recording(root) -> None:
    """A sound historical recording beside the current one (the :0.9.0 shape)."""
    import shutil

    from automated_security_helper.base.tool_transcript import file_sha256

    sarif = next(root.rglob("fixture-lint-1.0.0.sarif"))
    old = sarif.with_name("fixture-lint-0.9.0.sarif")
    shutil.copyfile(sarif, old)
    path = next(root.rglob("transcripts.json"))
    data = json.loads(path.read_text())
    historical = json.loads(json.dumps(data["transcripts"][0]))
    historical.update(
        id="fixture-lint-0.9.0-app",
        retention="historical",
        reason="the previous release's output shape",
        tool={"name": "fixture-lint", "version": "0.9.0"},
        results=[
            {
                "format": "sarif",
                "path": "captured/fixture-lint-0.9.0.sarif",
                "sha256": file_sha256(old),
            }
        ],
    )
    data["transcripts"].append(historical)
    path.write_text(json.dumps(data), encoding="utf-8")


def test_planted_a_current_recording_that_failed_its_digest_is_one_finding(
    fixture_manifest, transcripts_copy
) -> None:
    """The cause row is the finding: with the current recording out on its digest and
    only a historical one left sound, the per-facet MAPPED judgments would restate
    'no current recording' once per facet on top of the digest detail that already
    names why. One cause, one detail; the N/A and DROPPED cells are still judged
    over the historical corpus."""
    _plant_a_historical_recording(transcripts_copy)
    sarif = next(transcripts_copy.rglob("fixture-lint-1.0.0.sarif"))
    sarif.write_text(sarif.read_text().replace("FX001", "FX999"), encoding="utf-8")
    report = _verify(fixture_manifest, transcripts_copy)
    _expect(report, r1=RED)
    details = " ".join(_row(report, 1).details)
    assert "no longer matches the digest" in details
    assert "declared mapped" not in details
    # the skip is only of the MAPPED judgments: the rest are judged over every
    # readable recording, so the verdict list is not empty
    assert report.verdicts and all(v.facet for v in report.verdicts)


def test_a_historical_only_corpus_with_no_cause_recorded_still_fails_mapped_cells(
    fixture_manifest, transcripts_copy
) -> None:
    """The guard on the skip: an unpinned scanner whose only recording is historical
    records no cause row (the pinned-but-historical detail needs a pin), so its
    MAPPED cells are still judged and red rather than silently absent."""
    _plant_a_historical_recording(transcripts_copy)
    path = next(transcripts_copy.rglob("transcripts.json"))
    data = json.loads(path.read_text())
    data["transcripts"] = [
        t for t in data["transcripts"] if t["retention"] == "historical"
    ]
    path.write_text(json.dumps(data), encoding="utf-8")
    report = _verify(fixture_manifest, transcripts_copy)
    _expect(report, r1=RED)
    details = " ".join(_row(report, 1).details)
    assert "fixture-lint.file_path declared mapped" in details


def test_an_unreadable_only_current_set_stays_red_not_silently_green(
    fixture_manifest, transcripts_copy
) -> None:
    """The other guard on the skip: the skip's premise is that the cause of 'no
    current frame' is already a detail on the row, and a current recording that
    ``_readable`` leaves out (native bytes, no adapter prep) used to record none.
    With a sound historical recording beside it the N/A cells read ok over the
    historical corpus, the MAPPED judgments are skipped, and before the fix the row
    read GREEN with no facet observed (the live shape: a corpus scanner's one
    readable current SARIF entry losing its ``adapter_prep``)."""
    _plant_a_historical_recording(transcripts_copy)
    path = next(transcripts_copy.rglob("transcripts.json"))
    data = json.loads(path.read_text())
    current = next(
        t for t in data["transcripts"] if t.get("retention", "current") == "current"
    )
    for entry in current["results"]:
        entry["format"] = "json"
    path.write_text(json.dumps(data), encoding="utf-8")
    report = _verify(fixture_manifest, transcripts_copy)
    _expect(report, r1=RED)
    details = " ".join(_row(report, 1).details)
    assert "cannot be read as findings" in details
    assert current["id"] in details


def test_an_unreadable_current_recording_beside_a_readable_one_stays_quiet(
    fixture_manifest, transcripts_copy
) -> None:
    """The scope of the guard above: the shipped corpus keeps current native-bytes
    recordings beside readable current ones on purpose, so an excluded current
    transcript is named only when it leaves the scanner with no current frame at
    all."""
    path = next(transcripts_copy.rglob("transcripts.json"))
    data = json.loads(path.read_text())
    unreadable = json.loads(json.dumps(data["transcripts"][0]))
    unreadable["id"] = "fixture-lint-native-bytes"
    for entry in unreadable["results"]:
        entry["format"] = "json"
    data["transcripts"].append(unreadable)
    path.write_text(json.dumps(data), encoding="utf-8")
    report = _verify(fixture_manifest, transcripts_copy)
    _expect(report)


def test_planted_an_unrecorded_row_names_what_to_record(
    fixture_manifest, transcripts_copy
) -> None:
    path = next(transcripts_copy.rglob("transcripts.json"))
    document = json.loads(path.read_text())
    document["transcripts"] = []
    document["unrecorded"] = [
        {"scanner": "fixture-lint", "reason": "record fixture-lint over input/app.py"}
    ]
    path.write_text(json.dumps(document), encoding="utf-8")
    detail = _row(_verify(fixture_manifest, transcripts_copy), 1).details[0]
    assert "record fixture-lint over input/app.py" in detail


def test_planted_a_pin_bump_turns_row_one_red_until_rerecorded(
    fixture_manifest, transcripts_copy
) -> None:
    path = next(transcripts_copy.rglob("transcripts.json"))
    document = json.loads(path.read_text())
    document["transcripts"][0]["pin_stamp"] = {
        "tool": "fixture-lint",
        "version": "1.0.0",
    }
    path.write_text(json.dumps(document), encoding="utf-8")
    fresh = _verify(fixture_manifest, transcripts_copy, pins={"fixture-lint": "1.0.0"})
    _expect(fresh)
    bumped = _verify(fixture_manifest, transcripts_copy, pins={"fixture-lint": "1.1.0"})
    _expect(bumped, r1=RED)
    assert "recorded at fixture-lint 1.0.0 but the manifest pins 1.1.0" in " ".join(
        _row(bumped, 1).details
    )


def test_planted_a_mapped_cell_whose_column_the_tool_stopped_filling_fails(
    fixture_manifest, transcripts_copy
) -> None:
    """The tool's output moved: the recorded results no longer carry a location."""
    sarif = next(transcripts_copy.rglob("fixture-lint-1.0.0.sarif"))
    document = json.loads(sarif.read_text())
    for result in document["runs"][0]["results"]:
        del result["locations"]
    sarif.write_text(json.dumps(document), encoding="utf-8")
    _restamp_digest(transcripts_copy, sarif)
    report = _verify(fixture_manifest, transcripts_copy)
    _expect(report, r1=RED)
    details = " ".join(_row(report, 1).details)
    assert "fixture-lint.file_path declared mapped" in details
    assert "fixture-lint.line_range declared mapped" in details
    assert "fixture-lint.rule_id" not in details


def test_planted_an_na_cell_whose_column_is_now_populated_fails(
    fixture_manifest, transcripts_copy
) -> None:
    """A value reached a column the register says is impossible (a tag appeared)."""
    sarif = next(transcripts_copy.rglob("fixture-lint-1.0.0.sarif"))
    document = json.loads(sarif.read_text())
    document["runs"][0]["results"][0]["properties"] = {"tags": ["injected"]}
    sarif.write_text(json.dumps(document), encoding="utf-8")
    _restamp_digest(transcripts_copy, sarif)
    report = _verify(fixture_manifest, transcripts_copy)
    _expect(report, r1=RED)
    assert "fixture-lint.tags declared n/a" in " ".join(_row(report, 1).details)


def test_planted_a_transcript_that_cannot_be_read_as_results_leaves_mapped_cells_corpusless(
    fixture_manifest, transcripts_copy
) -> None:
    """The one current recording is marked not observable: nothing can witness the
    facets, and the row names that recording rather than reading green (or restating
    the cause once per facet)."""
    path = next(transcripts_copy.rglob("transcripts.json"))
    document = json.loads(path.read_text())
    document["transcripts"][0]["observable"] = False
    path.write_text(json.dumps(document), encoding="utf-8")
    report = _verify(fixture_manifest, transcripts_copy)
    _expect(report, r1=RED)
    details = " ".join(_row(report, 1).details)
    assert "cannot be read as findings" in details
    assert "it is marked not observable" in details


def _restamp_digest(root, sarif) -> None:
    """Move the recorded digest with the edited bytes, so only the facet judgment is left."""
    from automated_security_helper.base.tool_transcript import file_sha256

    path = next(root.rglob("transcripts.json"))
    document = json.loads(path.read_text())
    document["transcripts"][0]["results"][0]["sha256"] = file_sha256(sarif)
    path.write_text(json.dumps(document), encoding="utf-8")


# ---- row 2: operational declarations --------------------------------------


def test_every_kind_of_unconfirmed_cell_is_found() -> None:
    from automated_security_helper.base import scanner_operational_facets as opsf

    class Holder(BaseModel):
        unconfirmed: str | None = None
        layers: tuple = ()
        klass: object = None
        provenance: object = None

    layer = opsf.SilencingLayer(
        layer=opsf.SilencingLayerKind.INLINE_COMMENT,
        writer=opsf.SilencingWriter.REPOSITORY,
        honored=opsf.Honored.UNCONFIRMED,
        surface="a pragma",
        reason="read a run with the pragma present",
        cite="x.py",
    )
    holder = Holder(
        unconfirmed="behavior on a non-checkout was not read",
        layers=(layer,),
        klass=opsf.FingerprintClass.UNCONFIRMED,
        provenance=ProvenanceFacet(
            source=ProvenanceSource.USER_INSTALLED,
            selection_surfaces=(),
            upstream_license=LICENSE_NOT_READ,
        ),
    )
    found = list(unconfirmed_cells(holder))
    assert len(found) == 4, found
    assert any("behavior on a non-checkout was not read" in f for f in found)
    assert any("layers[0].honored: unconfirmed" in f for f in found)
    assert any("klass: unconfirmed" in f for f in found)
    assert any("provenance.upstream_license: not read" in f for f in found)


def test_an_unconfirmed_cell_inside_a_mapping_or_a_set_is_found() -> None:
    from automated_security_helper.base import scanner_operational_facets as opsf

    class Holder(BaseModel):
        by_name: dict = {}
        members: frozenset = frozenset()
        plain: set = set()

    holder = Holder(
        by_name={"a": opsf.FingerprintClass.UNCONFIRMED, "b": ("fine",)},
        members=frozenset({opsf.Honored.UNCONFIRMED}),
        plain={LICENSE_NOT_READ},
    )
    found = sorted(unconfirmed_cells(holder))
    assert len(found) == 3, found
    assert any(f.startswith("by_name['a']") for f in found)
    assert any(f.startswith("members{0}") for f in found)
    assert any(f.startswith("plain{0}") for f in found)
    # the control: a holder with the same shapes and nothing unconfirmed reads clean
    assert not list(
        unconfirmed_cells(
            Holder(by_name={"b": ("fine",)}, members=frozenset({1}), plain={"x"})
        )
    )


def test_a_row_is_read_from_the_class_that_declares_it_not_from_a_parent(
    fixture_manifest,
) -> None:
    """One lookup rule for every register: a subclass that inherits a parent's operational
    row has declared none, so row 2 is red for it rather than judged on the parent's."""
    from ash_fixture_plugin.scanner import FixtureScanner

    from automated_security_helper.core import plugin_conformance as conformance

    class Child(FixtureScanner):
        pass

    assert conformance._own_row(FixtureScanner, "operational_facets") is not None
    assert conformance._own_row(Child, "operational_facets") is None
    assert conformance._own_row(Child, "facets") is None


def test_a_confirmed_row_has_no_unconfirmed_cell(fixture_manifest) -> None:
    from ash_fixture_plugin.scanner import FixtureScanner

    assert list(unconfirmed_cells(FixtureScanner.operational_facets)) == []


def test_planted_an_unconfirmed_cell_turns_row_two_red_and_only_row_two(
    fixture_manifest, transcripts_copy
) -> None:
    from ash_fixture_plugin.scanner import FixtureScanner

    from automated_security_helper.base import scanner_operational_facets as opsf

    original = FixtureScanner.operational_facets
    FixtureScanner.operational_facets = original.model_copy(
        update={
            "identity": opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.UNCONFIRMED,
                note="not read at a fixture yet",
            )
        }
    )
    try:
        report = _verify(fixture_manifest, transcripts_copy)
    finally:
        FixtureScanner.operational_facets = original
    _expect(report, r2=RED)
    assert "identity.fingerprint_class: unconfirmed" in _row(report, 2).details[0]


# ---- row 3: the live cell --------------------------------------------------


def test_planted_a_red_live_cell_turns_row_three_red(
    fixture_manifest, transcripts_copy
) -> None:
    report = _verify(fixture_manifest, transcripts_copy, live_results={"host": False})
    _expect(report, r3=RED)
    assert "the live cell is red on host" in _row(report, 3).details[0]
    assert report.verdict == "fail"


def test_a_live_result_for_the_wrong_platform_is_not_a_pass(
    fixture_manifest, transcripts_copy
) -> None:
    report = _verify(
        fixture_manifest, transcripts_copy, live_results={"linux/amd64": True}
    )
    _expect(report, r3=RED)
    assert "no live-cell result for host" in _row(report, 3).details[0]


# ---- row 4: provisioning ---------------------------------------------------


def test_planted_a_user_installed_cli_with_no_stated_prerequisites_turns_row_four_red(
    fixture_manifest, transcripts_copy
) -> None:
    from ash_fixture_plugin.scanner import FixtureScanner

    from automated_security_helper.base import scanner_operational_facets as opsf

    original = FixtureScanner.operational_facets
    blank = original.prerequisites.model_copy(update={"note": "   "})
    FixtureScanner.operational_facets = original.model_copy(
        update={"prerequisites": blank}
    )
    try:
        report = _verify(fixture_manifest, transcripts_copy)
    finally:
        FixtureScanner.operational_facets = original
    _expect(report, r4=RED)
    assert "states its prerequisites" in _row(report, 4).details[0]
    assert isinstance(blank, opsf.PrerequisitesFacet)


def test_a_package_installed_tool_is_not_run_not_green(
    fixture_manifest, transcripts_copy
) -> None:
    """A uv-installed tool's pin is its package lock, which no manifest declares yet."""
    from ash_fixture_plugin.scanner import FixtureScanner

    from automated_security_helper.base import scanner_operational_facets as opsf

    original = FixtureScanner.operational_facets
    runtime = opsf.RuntimeFacet(
        kind=opsf.RuntimeKind.PYPI_PACKAGE,
        external_programs=(),
        invocations=opsf.Invocations.ONE,
        python_only=False,
        use_uv_tool=False,
    )
    FixtureScanner.operational_facets = original.model_copy(update={"runtime": runtime})
    try:
        report = _verify(fixture_manifest, transcripts_copy)
    finally:
        FixtureScanner.operational_facets = original
    _expect(report, r4=NOT_RUN)
    assert "package lock" in _row(report, 4).details[0]


# ---- row 5 and the verdict -------------------------------------------------


def test_the_docs_row_is_never_green_while_no_generator_exists(
    fixture_manifest, transcripts_copy
) -> None:
    row = _row(_verify(fixture_manifest, transcripts_copy), 5)
    assert row.status is NOT_RUN and "generator" in row.details[0]


def test_verification_runs_no_tool_and_writes_nothing(
    fixture_manifest, transcripts_copy, monkeypatch
) -> None:
    def no_process(*args, **kwargs):
        raise AssertionError(f"verification started a process: {args!r}")

    monkeypatch.setattr(subprocess, "Popen", no_process)
    before = sorted(
        (p.relative_to(transcripts_copy).as_posix(), p.read_bytes())
        for p in transcripts_copy.rglob("*")
        if p.is_file()
    )
    _verify(fixture_manifest, transcripts_copy)
    after = sorted(
        (p.relative_to(transcripts_copy).as_posix(), p.read_bytes())
        for p in transcripts_copy.rglob("*")
        if p.is_file()
    )
    assert before == after
