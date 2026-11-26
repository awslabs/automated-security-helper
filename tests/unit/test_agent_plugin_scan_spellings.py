# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Where an agent plugin tells the user to run ``ash scan fs``, it names the older form too.

Why this file exists
--------------------
The agent plugins start ASH's MCP server from a pinned release, the current one, and
for a container scan they tell the user to run the ASH command line instead. That
command line is whatever ASH the user installed, which the install pages pin to the
same release; an ASH older than 3.9 has no ``ash scan fs`` and refuses it. So a plugin
that names the subject spelling names the spelling an older ASH reads beside it, and
the ``ash --version`` boundary between them.

What is asserted
----------------
In the transpiler's sources (``_base/`` and ``templates/``) and in every output it
generates (``plugins/`` and the repository's ``skills/``), each mention of
``ash scan fs`` is followed, within the same sentence or the next, by the words
"older than 3.9". The control is that the sources do mention ``ash scan fs``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
TRANSPILER = REPO_ROOT / "ash-agent-plugins" / "agentic-coding" / "transpiler"
ROOTS = [
    TRANSPILER / "_base",
    TRANSPILER / "templates",
    REPO_ROOT / "ash-agent-plugins" / "agentic-coding" / "plugins",
    REPO_ROOT / "skills",
]
MENTION = "`ash scan fs"
OLDER = "older than 3.9"
#: How far after a mention the older form must be named: the rest of its sentence
#: and the next one.
WINDOW = 300


def _texts() -> dict[str, str]:
    texts = {}
    for root in ROOTS:
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.suffix not in {".md", ".mdc", ".j2"}:
                continue
            text = " ".join(path.read_text(encoding="utf-8").split())
            if MENTION in text:
                texts[str(path.relative_to(REPO_ROOT))] = text
    return texts


TEXTS = _texts()


def test_the_sources_mention_the_subject_spelling():
    sources = [rel for rel in TEXTS if "/transpiler/" in rel]
    assert sources, "control: no plugin source mentions `ash scan fs` any more"


@pytest.mark.parametrize("rel", sorted(TEXTS))
def test_each_mention_of_ash_scan_fs_names_the_older_form(rel):
    text = TEXTS[rel]
    start = 0
    while (found := text.find(MENTION, start)) != -1:
        window = text[found : found + WINDOW]
        assert OLDER in window, (
            f"{rel} tells the user to run `ash scan fs` without the form an ASH older "
            f"than 3.9 reads: {window!r}"
        )
        start = found + len(MENTION)
