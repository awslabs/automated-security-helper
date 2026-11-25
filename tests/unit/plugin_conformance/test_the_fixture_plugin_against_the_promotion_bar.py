# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The conformance harness over the fixture plugin: the positive control, then one
planted defect per row (design 4.5, unit A6).

The fixture plugin is the smallest plugin that conforms. Every row of the bar that can be
read without CI is green over it; each planted-defect test breaks exactly one thing in a
private copy and expects exactly the one row that guards it to go red, and the rest to
stay as they were. A row that cannot go red on a planted defect is documentation.
"""

import json

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


# ---- row 1: facets over committed transcripts ------------------------------


def test_planted_an_edited_results_file_turns_row_one_red(
    fixture_manifest, transcripts_copy
) -> None:
    sarif = next(transcripts_copy.rglob("fixture-lint-1.0.0.sarif"))
    sarif.write_text(sarif.read_text().replace("FX001", "FX999"), encoding="utf-8")
    report = _verify(fixture_manifest, transcripts_copy)
    assert _status(report)[1] is RED
    assert "no longer matches the digest" in " ".join(_row(report, 1).details)
    assert report.exit_code == EXIT_FAIL
    assert {n: s for n, s in _status(report).items() if n != 1} == {
        2: GREEN,
        3: NOT_RUN,
        4: GREEN,
        5: NOT_RUN,
    }


def test_planted_a_removed_transcript_turns_row_one_red_naming_the_scanner(
    fixture_manifest, transcripts_copy
) -> None:
    next(transcripts_copy.rglob("transcripts.json")).unlink()
    report = _verify(fixture_manifest, transcripts_copy)
    assert _status(report)[1] is RED
    assert "fixture-lint has no recorded transcript" in _row(report, 1).details[0]


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
    assert _status(fresh)[1] is GREEN
    bumped = _verify(fixture_manifest, transcripts_copy, pins={"fixture-lint": "1.1.0"})
    assert _status(bumped)[1] is RED
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
    assert _status(report)[1] is RED
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
    assert _status(report)[1] is RED
    assert "fixture-lint.tags declared n/a" in " ".join(_row(report, 1).details)


def test_planted_a_transcript_that_cannot_be_read_as_results_leaves_mapped_cells_corpusless(
    fixture_manifest, transcripts_copy
) -> None:
    path = next(transcripts_copy.rglob("transcripts.json"))
    document = json.loads(path.read_text())
    document["transcripts"][0]["observable"] = False
    path.write_text(json.dumps(document), encoding="utf-8")
    report = _verify(fixture_manifest, transcripts_copy)
    assert _status(report)[1] is RED
    assert "has no corpus to observe" in " ".join(_row(report, 1).details)


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
    assert _status(report) == {1: GREEN, 2: RED, 3: NOT_RUN, 4: GREEN, 5: NOT_RUN}
    assert "identity.fingerprint_class: unconfirmed" in _row(report, 2).details[0]


# ---- row 3: the live cell --------------------------------------------------


def test_planted_a_red_live_cell_turns_row_three_red(
    fixture_manifest, transcripts_copy
) -> None:
    report = _verify(fixture_manifest, transcripts_copy, live_results={"host": False})
    assert _status(report)[3] is RED
    assert "the live cell is red on host" in _row(report, 3).details[0]
    assert report.verdict == "fail"


def test_a_live_result_for_the_wrong_platform_is_not_a_pass(
    fixture_manifest, transcripts_copy
) -> None:
    report = _verify(
        fixture_manifest, transcripts_copy, live_results={"linux/amd64": True}
    )
    assert _status(report)[3] is RED
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
    assert _status(report)[4] is RED
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
    assert _status(report)[4] is NOT_RUN
    assert "package lock" in _row(report, 4).details[0]


# ---- row 5 and the verdict -------------------------------------------------


def test_the_docs_row_is_never_green_while_no_generator_exists(
    fixture_manifest, transcripts_copy
) -> None:
    row = _row(_verify(fixture_manifest, transcripts_copy), 5)
    assert row.status is NOT_RUN and "generator" in row.details[0]


def test_verification_runs_no_tool_and_writes_nothing(
    fixture_manifest, transcripts_copy
) -> None:
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
