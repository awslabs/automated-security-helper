# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The freshness gate over the committed fixture corpus.

Every fixture directory under ``tests/test_data/scanners`` that holds recorded tool
output carries a ``transcripts.json``. This is the register consistency test the corpus
needs: it refuses a transcript whose bytes moved, whose stamp differs from the pin the
plugin's manifest declares now, or which names a scanner that has no manifest, and it
refuses a manifest scanner that no transcript file accounts for. A pin bump therefore
forces either a re-record or a red test naming the stale transcript.

There is no skip list and no waiver here. A recording that is kept at another version on
purpose says so in its own transcript (``retention: historical`` with a reason), which is
reviewed with the fixture; the only other exit is to re-record.
"""

import json
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_provisioning import tool_versions
from automated_security_helper.base.tool_transcript import (
    TRANSCRIPT_FILE_NAME,
    stale_transcripts,
    verify_digests,
)
from automated_security_helper.core.plugin_conformance import (
    PREPS,
    discover_transcript_files,
)
from automated_security_helper.plugin_manifests import scanner_manifests

pytestmark = pytest.mark.unit

_ROOT = Path(__file__).resolve().parents[2] / "test_data" / "scanners"
_FILES = discover_transcript_files(_ROOT)
_TRANSCRIPTS = [(base, t) for base, f in _FILES for t in f.transcripts]
_MANIFESTS = {m.name: m for m in scanner_manifests()}
_PINNED_SCANNERS = {
    m.name: m.provisioning.tool_pins[0].tool
    for m in scanner_manifests()
    if m.provisioning.tool_pins
}


def _id(item) -> str:
    return f"{item[0].name}/{item[1].id}"


def test_the_gate_is_not_vacuous() -> None:
    """A gate over an empty corpus passes everything; refuse that."""
    assert len(_FILES) >= 18, [b.name for b, _ in _FILES]
    assert len(_TRANSCRIPTS) >= 60
    assert {t.retention for _b, t in _TRANSCRIPTS} == {"current", "historical"}
    stamped = [t for _b, t in _TRANSCRIPTS if t.pin_stamp is not None]
    assert len(stamped) >= 15, "the pinned scanners' recordings carry their stamps"


def test_the_gate_carries_no_waiver() -> None:
    """The gate has no skip, xfail or allowlist; the only exits are re-record or a
    transcript that declares itself historical."""
    source = Path(__file__).read_text(encoding="utf-8")
    # The needles are built by concatenation so this file does not contain them; the
    # whole file is read, this test and every gate test after it included.
    needles = (
        "pytest." + "skip(",
        "pytest." + "xfail(",
        "importor" + "skip(",
        "mark." + "skip",
        "mark." + "xfail",
    )
    for needle in needles:
        assert needle not in source, needle


@pytest.mark.parametrize("item", _TRANSCRIPTS, ids=_id)
def test_a_committed_transcript_matches_the_bytes_it_names(item) -> None:
    base, transcript = item
    assert verify_digests(transcript, base) == []


@pytest.mark.parametrize("item", _TRANSCRIPTS, ids=_id)
def test_a_committed_transcript_names_scanners_that_have_manifests(item) -> None:
    _base, transcript = item
    for scanner in transcript.scanners:
        assert scanner in _MANIFESTS, f"{transcript.id}: no manifest for {scanner!r}"


@pytest.mark.parametrize("item", _TRANSCRIPTS, ids=_id)
def test_a_committed_transcripts_adapter_prep_is_registered(item) -> None:
    _base, transcript = item
    if transcript.adapter_prep is not None:
        assert transcript.adapter_prep in PREPS, transcript.id


def test_no_committed_transcript_is_stale_against_the_manifests_pins() -> None:
    """The freshness gate: a stamp differing from the pin in force is red, naming it."""
    problems = stale_transcripts(
        (t for _b, t in _TRANSCRIPTS), tool_versions(), _PINNED_SCANNERS
    )
    assert problems == [], "\n".join(problems)


def test_every_scanner_with_a_manifest_is_accounted_for_by_a_transcript_file() -> None:
    """A manifest scanner is either recorded or listed unrecorded with what to record."""
    recorded = {s for _b, t in _TRANSCRIPTS for s in t.scanners}
    unrecorded = {u.scanner for _b, f in _FILES for u in f.unrecorded}
    assert not recorded & unrecorded, sorted(recorded & unrecorded)
    missing = sorted(set(_MANIFESTS) - recorded - unrecorded)
    assert not missing, (
        f"{missing} have a manifest but neither a transcript nor an unrecorded row "
        "in any transcripts.json: record one, or list the scanner as unrecorded "
        "with what to record"
    )
    assert not (recorded | unrecorded) - set(_MANIFESTS)


def test_every_scanner_that_pins_its_tool_has_a_stamped_current_recording_or_none() -> (
    None
):
    """Pinned scanners' current recordings are stamped (the stale rule enforces the
    stamp); this names which pinned scanners have no current recording yet, so the
    count cannot silently grow."""
    without_current = sorted(
        scanner
        for scanner in _PINNED_SCANNERS
        if not any(
            t.retention == "current" and scanner in t.scanners for _b, t in _TRANSCRIPTS
        )
    )
    # syft: its only committed recording predates the pin (syft 1.22.0) and is kept as
    # historical until re-recorded at the pin. grype has a current recording at its pin
    # (0.122.1) beside its historical 0.91.0 one.
    assert without_current == ["syft"]


def test_the_freshness_control_planted_pin_bump_names_every_current_transcript() -> (
    None
):
    """Must-flag through the real data: bump hadolint's pin and each of its five current
    recordings is named. Must-not-flag: the same data at the real pin is clean."""
    hadolint = [t for _b, t in _TRANSCRIPTS if t.scanner == "hadolint"]
    assert len(hadolint) == 5
    assert stale_transcripts(hadolint, tool_versions(), _PINNED_SCANNERS) == []
    bumped = {**tool_versions(), "hadolint": "v99.0.0"}
    problems = stale_transcripts(hadolint, bumped, _PINNED_SCANNERS)
    assert len(problems) == 5
    assert all("manifest pins v99.0.0" in p for p in problems)
    assert {p.split(":")[0] for p in problems} == {t.id for t in hadolint}


def test_the_historical_recordings_are_the_ones_older_than_their_pin() -> None:
    historical = {t.id for _b, t in _TRANSCRIPTS if t.retention == "historical"}
    assert historical == {
        "cfn-guard-3.2.1-wa-security-pillar-and-cis-aws-benchmark-level-1-insecure",
        "cfn-guard-3.2.1-wa-security-pillar-compliant",
        "cfn-guard-3.2.1-wa-security-pillar-insecure",
        "grype-0.91.0-src",
        "syft-1.22.0-src",
        "trivy-0.69.3-all",
        "trivy-0.69.3-vuln",
        "trivy-0.75.0-shared-cve",
    }


def test_a_transcript_file_is_found_by_its_name_alone(tmp_path) -> None:
    """Discovery needs no list: every directory holding a ``transcripts.json`` is one
    discovery returns, so a new fixture directory cannot be forgotten.

    Proven over a planted tree discovery has never seen. The committed corpus cannot
    prove it: ``_FILES`` is built by the same ``rglob`` a comparison there would use,
    so that comparison could not fail."""
    import shutil

    donor = next(_ROOT.rglob(TRANSCRIPT_FILE_NAME))
    for name in ("a", "b/nested"):
        target = tmp_path / name
        target.mkdir(parents=True)
        shutil.copyfile(donor, target / TRANSCRIPT_FILE_NAME)
    (tmp_path / "c").mkdir()  # no transcripts.json: not a fixture directory
    found = discover_transcript_files(tmp_path)
    assert {base for base, _ in found} == {tmp_path / "a", tmp_path / "b" / "nested"}


def test_the_committed_files_are_in_the_canonical_text() -> None:
    """A re-record diffs by content only if every writer emits the same text."""
    from automated_security_helper.base.tool_transcript import (
        dump_transcript_file,
        load_transcript_file,
    )

    for path in sorted(_ROOT.rglob(TRANSCRIPT_FILE_NAME)):
        text = path.read_text(encoding="utf-8")
        assert dump_transcript_file(load_transcript_file(path)) == text, path
        json.loads(text)
