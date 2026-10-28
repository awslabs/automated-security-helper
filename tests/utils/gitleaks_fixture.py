# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The gitleaks fixture repository, materialized at test time.

The fixture's credentials are fabricated: generated for the tests, never issued
by GitHub, AWS or Slack. They still match the providers' token formats closely
enough for GitHub push protection to refuse a commit holding them, which is what
it is for. So the committed tree, ``tests/test_data/scanners/gitleaks/repo_template``,
holds ``@@<name>@@`` markers instead, and the values are stored reversed in
``fabricated_tokens.reversed.json`` beside it, a form no token pattern matches.

``materialize`` writes the real tree. The committed capture
``gitleaks-8.30.1.sarif`` was produced from exactly that tree, so its paths,
lines and columns hold for every materialized copy.
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

DATA = Path(__file__).resolve().parents[1] / "test_data" / "scanners" / "gitleaks"
TEMPLATE = DATA / "repo_template"
_TOKENS = DATA / "fabricated_tokens.reversed.json"
_MARKER = re.compile(r"@@([a-z_]+)@@")


def fabricated_tokens() -> dict[str, str]:
    """Marker name -> fabricated credential value."""
    reversed_tokens = json.loads(_TOKENS.read_text(encoding="utf-8"))
    return {name: value[::-1] for name, value in reversed_tokens.items()}


def materialize(dest: Path) -> Path:
    """Write the fixture repository to ``dest`` (which must not exist) and return it."""
    tokens = fabricated_tokens()
    shutil.copytree(TEMPLATE, dest)
    used = set()
    for path in dest.rglob("*"):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")

        def _sub(match: re.Match) -> str:
            used.add(match.group(1))
            return tokens[match.group(1)]

        new = _MARKER.sub(_sub, text)
        if new != text:
            path.write_text(new, encoding="utf-8", newline="\n")
    assert used == set(tokens), f"unused or missing markers: {set(tokens) ^ used}"
    return dest
