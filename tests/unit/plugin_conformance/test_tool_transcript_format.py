# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The ToolTranscript format: what it refuses, and the freshness rule (design 4.4)."""

import json

import pytest

from automated_security_helper.base.tool_transcript import (
    TRANSCRIPT_SCHEMA_VERSION,
    FixtureTree,
    PinStamp,
    ResultsFile,
    ToolRef,
    ToolTranscript,
    TranscriptFile,
    TranscriptSchemaError,
    Unrecorded,
    dump_transcript_file,
    file_sha256,
    load_transcript_file,
    parse_transcript_file,
    restamp,
    same_release,
    stale_transcripts,
    tree_sha256,
    verify_digests,
)

pytestmark = pytest.mark.unit

_SHA = "0" * 64


def _transcript(**overrides) -> ToolTranscript:
    fields = {
        "id": "t-1",
        "scanner": "gitleaks",
        "provenance": "attested",
        "tool": ToolRef(name="gitleaks", version="8.30.1"),
        "pin_stamp": PinStamp(tool="gitleaks", version="v8.30.1"),
        "results": (ResultsFile(path="out.sarif", sha256=_SHA, format="sarif"),),
    }
    fields.update(overrides)
    return ToolTranscript(**fields)


def _file(*transcripts, unrecorded=()) -> TranscriptFile:
    return TranscriptFile(
        schema_version=TRANSCRIPT_SCHEMA_VERSION,
        transcripts=tuple(transcripts),
        unrecorded=tuple(unrecorded),
    )


PINS = {"gitleaks": "v8.30.1"}


# ---- the shape ------------------------------------------------------------


def test_a_historical_transcript_states_why_and_only_a_historical_one_does() -> None:
    with pytest.raises(ValueError, match="historical transcript states why"):
        _transcript(retention="historical")
    with pytest.raises(ValueError, match="only a historical one does"):
        _transcript(reason="kept for old output")
    assert _transcript(retention="historical", reason="the old shape").reason


def test_a_captured_transcript_records_its_argv_and_exit_code() -> None:
    with pytest.raises(ValueError, match="argv and exit code"):
        _transcript(provenance="captured")
    assert _transcript(provenance="captured", argv=("gitleaks",), exit_code=0)


def test_an_attested_transcript_may_leave_argv_exit_and_stderr_unknown() -> None:
    transcript = _transcript()
    assert transcript.argv is None and transcript.exit_code is None
    assert transcript.stderr_tail is None


def test_a_transcript_names_at_least_one_results_file_once() -> None:
    with pytest.raises(ValueError):
        _transcript(results=())
    entry = ResultsFile(path="out.sarif", sha256=_SHA, format="sarif")
    with pytest.raises(ValueError, match="twice"):
        _transcript(results=(entry,), side_reports=(entry,))


@pytest.mark.parametrize("path", ["/abs.sarif", "a/../b.sarif", "a\\b.sarif", ""])
def test_a_results_path_is_relative_posix_without_dotdot(path: str) -> None:
    with pytest.raises(ValueError, match="relative posix path"):
        ResultsFile(path=path, sha256=_SHA, format="sarif")


def test_a_digest_is_sixty_four_lowercase_hex_digits() -> None:
    with pytest.raises(ValueError, match="64 lower-case hex"):
        ResultsFile(path="a", sha256="ABC", format="json")


def test_an_unknown_field_is_refused() -> None:
    with pytest.raises(ValueError):
        ToolTranscript.model_validate({**_transcript().model_dump(), "surprise": 1})


def test_a_scanner_is_recorded_or_unrecorded_in_one_file_never_both() -> None:
    with pytest.raises(ValueError, match="both recorded and listed as unrecorded"):
        _file(
            _transcript(),
            unrecorded=[Unrecorded(scanner="gitleaks", reason="more to record")],
        )


def test_a_transcript_id_is_unique_within_its_file() -> None:
    with pytest.raises(ValueError, match="used twice"):
        _file(_transcript(), _transcript())


def test_an_unrecorded_row_says_what_is_missing() -> None:
    with pytest.raises(ValueError, match="says what is missing"):
        Unrecorded(scanner="x", reason="  ")


def test_a_newer_schema_is_refused_in_prose_not_guessed() -> None:
    data = json.loads(dump_transcript_file(_file(_transcript())))
    data["schema_version"] = TRANSCRIPT_SCHEMA_VERSION + 1
    with pytest.raises(TranscriptSchemaError, match="upgrade ASH to read it"):
        parse_transcript_file(data)


def test_a_transcript_file_round_trips_byte_for_byte(tmp_path) -> None:
    text = dump_transcript_file(_file(_transcript()))
    path = tmp_path / "transcripts.json"
    path.write_text(text, encoding="utf-8")
    assert dump_transcript_file(load_transcript_file(path)) == text


# ---- the digests ----------------------------------------------------------


def _sound(tmp_path) -> ToolTranscript:
    (tmp_path / "out.sarif").write_text("{}\n", encoding="utf-8")
    (tmp_path / "in").mkdir()
    (tmp_path / "in" / "a.py").write_text("x = 1\n", encoding="utf-8")
    return _transcript(
        results=(
            ResultsFile(
                path="out.sarif",
                sha256=file_sha256(tmp_path / "out.sarif"),
                format="sarif",
            ),
        ),
        fixture_tree=FixtureTree(paths=("in",), sha256=tree_sha256(tmp_path, ("in",))),
    )


def test_sound_bytes_verify_clean(tmp_path) -> None:
    assert verify_digests(_sound(tmp_path), tmp_path) == []


def test_an_edited_results_file_is_named(tmp_path) -> None:
    transcript = _sound(tmp_path)
    (tmp_path / "out.sarif").write_text("{ }\n", encoding="utf-8")
    problems = verify_digests(transcript, tmp_path)
    assert len(problems) == 1 and "out.sarif no longer matches" in problems[0]


def test_a_missing_results_file_is_named(tmp_path) -> None:
    transcript = _sound(tmp_path)
    (tmp_path / "out.sarif").unlink()
    assert "out.sarif is not a file" in verify_digests(transcript, tmp_path)[0]


@pytest.mark.parametrize(
    "damage",
    ["edit", "add", "remove", "rename"],
)
def test_any_change_under_the_fixture_tree_moves_its_digest(tmp_path, damage) -> None:
    transcript = _sound(tmp_path)
    target = tmp_path / "in" / "a.py"
    if damage == "edit":
        target.write_text("x = 2\n", encoding="utf-8")
    elif damage == "add":
        (tmp_path / "in" / "b.py").write_text("y\n", encoding="utf-8")
    elif damage == "remove":
        target.unlink()
        (tmp_path / "in" / "keep").write_text("k\n", encoding="utf-8")
    else:
        target.rename(tmp_path / "in" / "c.py")
    problems = verify_digests(transcript, tmp_path)
    assert problems and "fixture tree" in problems[0]


def test_a_missing_fixture_tree_path_is_named(tmp_path) -> None:
    transcript = _sound(tmp_path)
    (tmp_path / "in" / "a.py").unlink()
    (tmp_path / "in").rmdir()
    assert "fixture tree path in is missing" in verify_digests(transcript, tmp_path)[0]


# ---- the freshness rule ---------------------------------------------------


def test_a_leading_v_does_not_make_two_releases_differ() -> None:
    assert same_release("v8.30.1", "8.30.1") and not same_release("8.30.1", "8.31.0")


def test_a_current_transcript_at_the_pin_is_fresh() -> None:
    assert stale_transcripts(_file(_transcript()).transcripts, PINS) == []


def test_a_pin_bump_turns_a_current_transcript_red_naming_it() -> None:
    problems = stale_transcripts(
        _file(_transcript()).transcripts, {"gitleaks": "v8.31.0"}
    )
    assert len(problems) == 1
    assert problems[0].startswith("t-1: recorded at gitleaks v8.30.1")
    assert "manifest pins v8.31.0" in problems[0] and "re-record" in problems[0]


def test_a_historical_transcript_stays_green_across_a_pin_bump() -> None:
    old = _transcript(
        retention="historical",
        reason="the previous release's output shape",
        pin_stamp=PinStamp(tool="gitleaks", version="v8.29.0"),
        tool=ToolRef(name="gitleaks", version="8.29.0"),
    )
    assert stale_transcripts([old], PINS) == []


def test_a_historical_transcript_at_the_pin_is_a_current_one() -> None:
    mislabeled = _transcript(retention="historical", reason="kept")
    problems = stale_transcripts([mislabeled], PINS)
    assert len(problems) == 1 and "it is a current transcript" in problems[0]


def test_a_stamp_for_a_tool_nothing_pins_is_refused() -> None:
    problems = stale_transcripts(_file(_transcript()).transcripts, {})
    assert len(problems) == 1 and "no manifest pins now" in problems[0]


def test_the_tool_version_recorded_must_match_the_stamp_of_a_current_transcript() -> (
    None
):
    liar = _transcript(tool=ToolRef(name="gitleaks", version="8.1.0"))
    problems = stale_transcripts([liar], PINS)
    assert len(problems) == 1 and "is not the version it is stamped with" in problems[0]


def test_an_unstamped_current_transcript_of_a_pinned_scanner_is_refused() -> None:
    unstamped = _transcript(pin_stamp=None)
    problems = stale_transcripts([unstamped], PINS, {"gitleaks": "gitleaks"})
    assert len(problems) == 1 and "carries no stamp" in problems[0]
    # a scanner with no pin has nothing to stamp
    assert stale_transcripts([unstamped], PINS, {}) == []
    # a historical one is allowed to be unstamped: it does not claim to be fresh
    old = _transcript(pin_stamp=None, retention="historical", reason="old")
    assert stale_transcripts([old], PINS, {"gitleaks": "gitleaks"}) == []


def test_the_unstamped_rule_covers_every_scanner_a_recording_serves() -> None:
    shared = _transcript(pin_stamp=None, scanner="trivy", also_for=("trivy-repo",))
    problems = stale_transcripts([shared], {"trivy": "v0.76.2"}, {"trivy": "trivy"})
    assert len(problems) == 1 and "trivy pins its tool" in problems[0]


def test_restamping_moves_the_stamp_and_the_tool_version_together() -> None:
    old = _transcript(
        retention="historical",
        reason="old",
        pin_stamp=PinStamp(tool="gitleaks", version="v8.29.0"),
        tool=ToolRef(name="gitleaks", version="8.29.0"),
    )
    fresh = restamp(old, PINS)
    assert fresh.retention == "current" and fresh.reason is None
    assert fresh.pin_stamp == PinStamp(tool="gitleaks", version="v8.30.1")
    assert fresh.tool.version == "v8.30.1"
    assert stale_transcripts([fresh], PINS) == []


def test_restamping_an_unstamped_transcript_changes_nothing() -> None:
    unstamped = _transcript(pin_stamp=None)
    assert restamp(unstamped, PINS) == unstamped
