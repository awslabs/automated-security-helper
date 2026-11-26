# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The committed transcript of the captured run, and the harness's composer-audit prep.

``tests/test_data/scanners/composer_audit/transcripts.json`` indexes the capture that
``captured/README.md`` records: an attested transcript (the README's argv and exit
status, the digests of the document and the two project files). The conformance harness
reads it through the ``composer-audit`` adapter prep, which converts the document with
the lock the transcript's fixture tree names. These tests go through the harness's own
reader (``core.plugin_conformance``), with a must-flag control for the prep's lock rule
and a must-not-flag one over the real recording. Nothing here runs Composer.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from automated_security_helper.base.tool_transcript import (
    load_transcript_file,
    verify_digests,
)
from automated_security_helper.core.plugin_conformance import (
    PREPS,
    discover_transcript_files,
    observe_transcripts,
    transcripts_of,
)
from automated_security_helper.plugin_modules.ash_composer_audit_plugins import (
    composer_install as ci,
)
from automated_security_helper.utils.scanner_names import SCANNER_TOOL_TYPES

pytestmark = pytest.mark.unit

FIXTURES = Path(__file__).resolve().parents[3] / "test_data" / "scanners"
BASE = FIXTURES / "composer_audit"


def _transcript():
    (transcript,) = load_transcript_file(BASE / "transcripts.json").transcripts
    return transcript


def _prep(transcript):
    (entry,) = transcript.results
    return list(PREPS["composer-audit"](transcript, BASE, BASE / entry.path))


def test_the_transcript_is_the_captured_run():
    transcript = _transcript()
    assert transcript.scanner == "composer-audit"
    assert transcript.retention == "current"
    assert transcript.provenance == "attested"
    assert transcript.adapter_prep == "composer-audit"
    assert transcript.tool.version == ci.COMPOSER_VERSION
    assert transcript.exit_code == 1
    assert transcript.argv[:2] == ("composer", "audit")
    assert "--format=json" in transcript.argv
    assert "--abandoned=report" in transcript.argv
    assert transcript.pin_stamp is None, "the manifest declares no tool pin"
    assert verify_digests(transcript, BASE) == []


def test_the_prep_yields_the_results_of_the_committed_sarif():
    """The prep converts as the golden test's rebuild does, so it reads the same
    findings the SARIF corpus holds, rule for rule and line for line."""
    ((report, results),) = _prep(_transcript())
    golden = json.loads((BASE / "captured" / "audit.sarif").read_text(encoding="utf-8"))
    (run,) = golden["runs"]
    assert len(results) == len(run["results"]) > 0
    assert [
        (r.ruleId, r.locations[0].physicalLocation.root.region.startLine)
        for r in results
    ] == [
        (g["ruleId"], g["locations"][0]["physicalLocation"]["region"]["startLine"])
        for g in run["results"]
    ]
    assert [rule.id for rule in report.runs[0].tool.driver.rules] == [
        rule["id"] for rule in run["tool"]["driver"]["rules"]
    ]


def test_the_prep_refuses_a_fixture_tree_that_names_no_lock():
    transcript = _transcript()
    tree = transcript.fixture_tree.model_copy(
        update={"paths": ("captured/composer.json.capture",)}
    )
    with pytest.raises(ValueError, match="names 0 lock files"):
        _prep(transcript.model_copy(update={"fixture_tree": tree}))


def test_the_prep_refuses_a_fixture_tree_that_names_two_locks():
    transcript = _transcript()
    tree = transcript.fixture_tree.model_copy(
        update={"paths": ("captured/composer.lock.capture", "elsewhere/composer.lock")}
    )
    with pytest.raises(ValueError, match="names 2 lock files"):
        _prep(transcript.model_copy(update={"fixture_tree": tree}))


def test_the_harness_reads_the_recording_as_findings():
    mine = transcripts_of("composer-audit", discover_transcript_files(FIXTURES))
    assert [t.id for _base, t in mine] == ["composer-2.11.3-vulnerable-abandoned"]
    observed = observe_transcripts(
        "composer-audit", mine, SCANNER_TOOL_TYPES["composer-audit"]
    )
    assert observed.problems == ()
    assert observed.current is not None
    non_null, total = observed.current["package_name"]
    assert total > 0 and non_null == total
