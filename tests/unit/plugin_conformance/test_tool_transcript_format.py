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
    TranscriptRestampError,
    TranscriptSchemaError,
    Unrecorded,
    dump_transcript_file,
    file_sha256,
    is_sha256,
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


@pytest.mark.parametrize(
    "path",
    [
        "/abs.sarif",
        "a/../b.sarif",
        "a\\b.sarif",
        "",
        "./out.sarif",
        "a/./b.sarif",
        "a//b.sarif",
        "dir/",
        ".",
    ],
)
def test_a_results_path_is_a_normalized_relative_posix_path(path: str) -> None:
    with pytest.raises(ValueError, match="relative posix path"):
        ResultsFile(path=path, sha256=_SHA, format="sarif")


@pytest.mark.parametrize("path", [".", "./", "a/./b"])
def test_a_fixture_tree_cannot_name_the_transcript_files_own_directory(
    path: str,
) -> None:
    """``.`` would hash ``transcripts.json`` itself, whose digest then never matches."""
    with pytest.raises(ValueError, match="relative posix path"):
        FixtureTree(paths=(path,), sha256=_SHA)


def test_recorded_on_is_a_date_when_given() -> None:
    assert _transcript(recorded_on="2026-11-25").recorded_on == "2026-11-25"
    for bad in ("2026-11-25T01:00:00Z", "25/11/2026", "yesterday", ""):
        with pytest.raises(ValueError, match="YYYY-MM-DD"):
            _transcript(recorded_on=bad)


def test_recorded_on_is_a_calendar_date_in_ascii_digits() -> None:
    """The shape alone admitted 2026-13-45 (no such month or day) and non-ASCII
    digits (``\\d`` matches every Unicode digit); both are refused."""
    with pytest.raises(ValueError, match="not a calendar date"):
        _transcript(recorded_on="2026-13-45")
    with pytest.raises(ValueError, match="not a calendar date"):
        _transcript(recorded_on="2026-02-30")
    # Eastern Arabic-Indic digits, length and dash positions matching
    with pytest.raises(ValueError, match="YYYY-MM-DD"):
        _transcript(recorded_on="٢٠٢٦-١١-٢٥")


def test_also_for_names_other_scanners_once_each() -> None:
    assert _transcript(also_for=("trivy-repo",)).scanners == ("gitleaks", "trivy-repo")
    with pytest.raises(ValueError, match="never the transcript's own scanner"):
        _transcript(also_for=("gitleaks",))
    with pytest.raises(ValueError, match="each once"):
        _transcript(also_for=("trivy-repo", "trivy-repo"))


def test_is_sha256_is_sixty_four_lowercase_hex_and_nothing_else() -> None:
    assert is_sha256("a" * 64)
    for bad in ("A" * 64, "g" * 64, "a" * 63, "", None, 7):
        assert not is_sha256(bad)


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


def test_a_scanner_a_recording_also_serves_is_not_unrecorded_in_that_file() -> None:
    shared = _transcript(scanner="trivy", also_for=("trivy-repo",))
    with pytest.raises(ValueError, match="both recorded and listed as unrecorded"):
        _file(
            shared,
            unrecorded=[Unrecorded(scanner="trivy-repo", reason="record it")],
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


@pytest.mark.parametrize("data", [[], "text", 3, None])
def test_a_transcript_file_that_is_not_an_object_is_refused_in_prose(data) -> None:
    with pytest.raises(TranscriptSchemaError, match="JSON object"):
        parse_transcript_file(data)


def test_a_numeric_string_schema_version_gets_the_upgrade_message_too() -> None:
    data = json.loads(dump_transcript_file(_file(_transcript())))
    data["schema_version"] = str(TRANSCRIPT_SCHEMA_VERSION + 1)
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
    old = _transcript(
        pin_stamp=None,
        retention="historical",
        reason="old",
        tool=ToolRef(name="gitleaks", version="8.29.0"),
    )
    assert stale_transcripts([old], PINS, {"gitleaks": "gitleaks"}) == []


def test_the_unstamped_rule_covers_every_scanner_a_recording_serves() -> None:
    shared = _transcript(pin_stamp=None, scanner="trivy", also_for=("trivy-repo",))
    problems = stale_transcripts([shared], {"trivy": "v0.76.2"}, {"trivy": "trivy"})
    assert len(problems) == 1 and "trivy pins its tool" in problems[0]


def test_a_stamp_naming_another_scanners_pin_never_goes_stale_so_it_is_refused() -> (
    None
):
    """A gitleaks recording copied from betterleaks' fixture keeps betterleaks' stamp."""
    pins = {"gitleaks": "v8.30.1", "betterleaks": "v1.2.3"}
    copied = _transcript(
        pin_stamp=PinStamp(tool="betterleaks", version="v1.2.3"),
        tool=ToolRef(name="gitleaks", version="1.2.3"),
    )
    problems = stale_transcripts([copied], pins, {"gitleaks": "gitleaks"})
    assert len(problems) == 1
    assert (
        "stamped with the pin of 'betterleaks' but gitleaks pins 'gitleaks'"
        in (problems[0])
    )
    # the same recording, stamped with its own scanner's pin, is clean
    assert stale_transcripts([_transcript()], pins, {"gitleaks": "gitleaks"}) == []
    # and with no scanner pin map there is nothing to compare against
    assert stale_transcripts([copied], pins, {}) == []


def test_the_stamp_check_covers_every_scanner_a_recording_serves() -> None:
    pins = {"trivy": "v0.76.2"}
    shared = _transcript(
        scanner="trivy",
        also_for=("trivy-repo",),
        pin_stamp=PinStamp(tool="trivy", version="v0.76.2"),
        tool=ToolRef(name="trivy", version="0.76.2"),
    )
    assert stale_transcripts([shared], pins, {"trivy-repo": "trivy"}) == []
    problems = stale_transcripts([shared], pins, {"trivy-repo": "other"})
    assert len(problems) == 1 and "trivy-repo pins 'other'" in problems[0]


def test_an_unstamped_historical_recording_of_the_pinned_release_is_a_current_one() -> (
    None
):
    pinned = {"gitleaks": "gitleaks"}
    at_pin = _transcript(pin_stamp=None, retention="historical", reason="kept")
    problems = stale_transcripts([at_pin], PINS, pinned)
    assert len(problems) == 1 and "it is a current transcript" in problems[0]
    older = _transcript(
        pin_stamp=None,
        retention="historical",
        reason="old",
        tool=ToolRef(name="gitleaks", version="8.29.0"),
    )
    assert stale_transcripts([older], PINS, pinned) == []


def _rerecord(name: str = "out.sarif", sha: str = "1" * 64) -> tuple[ResultsFile, ...]:
    return (ResultsFile(path=name, sha256=sha, format="sarif"),)


def _old_recording() -> ToolTranscript:
    return _transcript(
        retention="historical",
        reason="old",
        pin_stamp=PinStamp(tool="gitleaks", version="v8.29.0"),
        tool=ToolRef(name="gitleaks", version="8.29.0"),
    )


#: The new run's record every restamp carries (restamp requires it: the restamped
#: transcript attests to THIS run, not the one it replaces).
_RUN = {"argv": ("gitleaks", "detect", "--no-banner"), "exit_code": 0}


def test_restamping_after_a_rerecord_takes_the_version_the_run_reported() -> None:
    fresh = restamp(
        _old_recording(), PINS, observed_version="8.30.1", results=_rerecord(), **_RUN
    )
    assert fresh.retention == "current" and fresh.reason is None
    assert fresh.pin_stamp == PinStamp(tool="gitleaks", version="v8.30.1")
    # the tool's own spelling, not the manifest's: the pin is "v8.30.1"
    assert fresh.tool.version == "8.30.1"
    assert fresh.results == _rerecord()
    assert stale_transcripts([fresh], PINS) == []


def test_restamping_takes_the_new_runs_record_and_marks_it_captured() -> None:
    """A re-record replaces an attested transcript with a captured one; every field of
    the old run's record goes with it, because the old argv, date or environment kept
    on the new bytes would attest to a run that never produced them."""
    old = _old_recording()
    assert old.provenance == "attested" and old.argv is None
    fresh = restamp(
        old,
        PINS,
        observed_version="8.30.1",
        results=_rerecord(),
        argv=("gitleaks", "detect", "--no-banner"),
        exit_code=0,
        stderr_tail="leaks found: 2",
        recorded_on="2026-11-25",
        env_allowlist=("PATH",),
    )
    assert fresh.provenance == "captured"
    assert fresh.argv == ("gitleaks", "detect", "--no-banner")
    assert fresh.exit_code == 0
    assert fresh.stderr_tail == "leaks found: 2"
    assert fresh.recorded_on == "2026-11-25"
    assert fresh.env_allowlist == ("PATH",)


def test_restamping_drops_the_old_runs_record_fields_it_is_not_given() -> None:
    """The old run's stderr tail and date never survive onto the new bytes: left
    unstated by the new run, they come back unknown, not inherited."""
    old = _transcript(
        retention="historical",
        reason="old",
        pin_stamp=PinStamp(tool="gitleaks", version="v8.29.0"),
        tool=ToolRef(name="gitleaks", version="8.29.0"),
        provenance="captured",
        argv=("gitleaks", "detect"),
        exit_code=1,
        stderr_tail="the OLD run's tail",
        recorded_on="2020-01-01",
        env_allowlist=("HOME",),
    )
    fresh = restamp(old, PINS, observed_version="8.30.1", results=_rerecord(), **_RUN)
    assert fresh.exit_code == 0
    assert fresh.stderr_tail is None
    assert fresh.recorded_on is None
    assert fresh.env_allowlist == ()


def test_restamping_a_run_of_the_wrong_binary_still_trips_the_version_check() -> None:
    """The stray gitleaks 8.1.0 on PATH: the stamp moves, the version it printed stays."""
    liar = restamp(
        _old_recording(), PINS, observed_version="8.1.0", results=_rerecord(), **_RUN
    )
    problems = stale_transcripts([liar], PINS)
    assert len(problems) == 1 and "is not the version it is stamped with" in problems[0]


def test_restamping_refuses_when_neither_digests_nor_version_changed() -> None:
    old = _old_recording()
    with pytest.raises(TranscriptRestampError, match="nothing was re-recorded"):
        restamp(
            old,
            PINS,
            observed_version=old.tool.version,
            results=old.results,
            **_RUN,
        )


def test_restamping_a_byte_identical_rerecord_at_a_new_version_is_accepted() -> None:
    """A tool whose output carries no version (actionlint JSON, cdk-nag CSV, guarddog
    JSON) reproduces byte-identical results on a real re-record; the new version the
    run printed is the evidence the run happened, so the restamp is not refused."""
    old = _old_recording()
    fresh = restamp(old, PINS, observed_version="8.30.1", results=old.results, **_RUN)
    assert fresh.tool.version == "8.30.1"
    assert fresh.results == old.results
    assert fresh.retention == "current" and fresh.provenance == "captured"
    assert stale_transcripts([fresh], PINS) == []


def test_restamping_a_stamp_whose_pin_is_gone_is_a_readable_error() -> None:
    with pytest.raises(TranscriptRestampError, match="no manifest pins now"):
        restamp(
            _old_recording(), {}, observed_version="8.30.1", results=_rerecord(), **_RUN
        )


def test_restamping_an_unstamped_transcript_changes_nothing() -> None:
    unstamped = _transcript(pin_stamp=None)
    assert (
        restamp(unstamped, PINS, observed_version="8.30.1", results=_rerecord(), **_RUN)
        == unstamped
    )
