# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""No agent-plugin document pins ``severity_threshold="MEDIUM"``.

Why this file exists
--------------------
The agent plugins document that ``run_ash_scan``'s ``severity_threshold``
argument can only tighten the config's ``global_settings.severity_threshold``,
never loosen it. A document that nonetheless passes ``"MEDIUM"`` on every scan
silently tightens a project whose config says ``LOW``: the project's LOW
findings drop out of ``actionable_only`` results, and a "configurable via user
prompt" aside reads as if asking for LOW would change anything, which under the
default MEDIUM config it would not.

The pin lived in ``_base/commands/scan.md`` step 3 and in ``_base/skill.md``'s
example call, and the transpiler byte-copies both into every plugin backend and
into the root ``skills/`` copy, so two pins were twenty-one files. The fix
removes the argument from both sources: a scan uses the config's threshold, the
argument is passed only for a stricter level, and a looser level is a config
edit plus a re-scan.

What this asserts
-----------------
No file under ``ash-agent-plugins/`` or ``skills/`` passes
``severity_threshold="MEDIUM"``. A tightening example (``"HIGH"``) is fine and
not matched. The scan is denominated: the walk must find the two source files
it exists to guard, and the corpus must still document ``severity_threshold``
somewhere, so an empty walk or a renamed tree fails rather than passing
vacuously.

What is deliberately not asserted
---------------------------------
Other spellings of a pin (the scanner agent's ``severity_threshold="LOW"``) and
the pages under ``docs/``. This file guards the one pin the fix removed, in the
trees the transpiler owns.
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

#: The trees the transpiler owns: the source and every generated copy.
DOC_TREES = ("ash-agent-plugins", "skills")

#: The pin this test exists to keep out. A stricter-level example ("HIGH")
#: does not match.
PIN = 'severity_threshold="MEDIUM"'

#: The two files the pin lived in. Their presence is the denominator: if the
#: tree moves, this test must fail loudly, not scan nothing.
SOURCES = (
    "ash-agent-plugins/agentic-coding/transpiler/_base/commands/scan.md",
    "ash-agent-plugins/agentic-coding/transpiler/_base/skill.md",
)


def _doc_files() -> list[Path]:
    files: list[Path] = []
    for tree in DOC_TREES:
        root = REPO_ROOT / tree
        assert root.is_dir(), f"doc tree missing: {root}"
        files.extend(
            p
            for p in sorted(root.rglob("*"))
            if p.is_file() and p.suffix in {".md", ".mdc", ".j2"}
        )
    return files


def test_no_document_pins_the_medium_threshold():
    files = _doc_files()
    assert len(files) > 0, "the doc walk found nothing; the denominator is gone"
    for source in SOURCES:
        assert (REPO_ROOT / source).is_file(), f"guarded source missing: {source}"

    offenders = [
        str(p.relative_to(REPO_ROOT))
        for p in files
        if PIN in p.read_text(encoding="utf-8", errors="replace")
    ]
    assert offenders == [], (
        'severity_threshold="MEDIUM" is pinned again in: ' + ", ".join(offenders)
    )

    # Positive control: the corpus still documents the argument itself, so a
    # rename of the parameter (which would make the pin check vacuous) fails
    # here instead of passing silently.
    mentions = sum(
        1
        for p in files
        if "severity_threshold" in p.read_text(encoding="utf-8", errors="replace")
    )
    assert mentions > 0, "no document mentions severity_threshold at all"
