# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The committed JSON schemas are what ``generate_schemas`` emits now.

Why this file exists
--------------------
``automated_security_helper/schemas/*.json`` are generated from the config and
results models by ``automated_security_helper.schemas.generate_schemas``. Until
now the only check that they were current was a hosted CI step
(``ash-unified-ci.yml``: regenerate, then fail on any ``git status`` change under
``schemas/*.json``). A pytest run alone, such as a sharded venue or a developer's
unit tier, could not see a stale schema: a regeneration at one tip rewrote both
schema files while every unit-tier id stayed green.

This test makes the same comparison the CI step makes, in the unit tier: each
committed file must equal, byte for byte, what the generator writes for its
model. ``test_generate_schemas.py::TestSchemaInventoryIsClosed`` already pins
that the set of committed files is the set of generated models; this file pins
the bytes, and reports a name present on one side only as stale too so a single
assertion names everything a regeneration would change. Top-level files only,
as the CI pathspec: the vendored subpackages are not this generator's. When the
generator's inputs cannot import, the test skips rather than fails, so an
environment that cannot build the models reports nothing about the schemas.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict

import pytest

pytestmark = pytest.mark.unit

REGENERATE = "python -m automated_security_helper.schemas.generate_schemas"


def _generated() -> Dict[str, str]:
    """The text the generator writes for each model, keyed by model name."""
    try:
        from automated_security_helper.schemas.generate_schemas import (
            generate_schemas,
        )

        texts = generate_schemas("json")
    except ImportError as error:  # pragma: no cover - depends on the environment
        pytest.skip(f"the schema generator's inputs cannot import here: {error}")
    # The file branch writes the sorted, indented JSON plus one trailing newline.
    return {name: text + "\n" for name, text in texts.items()}


def _schemas_dir() -> Path:
    from automated_security_helper.schemas import generate_schemas

    return Path(generate_schemas.__file__).resolve().parent


def stale_schemas(committed: Dict[str, str], generated: Dict[str, str]) -> list[str]:
    """The model names whose committed text differs from the generated text,
    and the names present on one side only; empty when every schema is current."""
    names = sorted(set(committed) | set(generated))
    return [name for name in names if committed.get(name) != generated.get(name)]


def test_every_committed_schema_matches_its_generator() -> None:
    generated = _generated()
    schemas_dir = _schemas_dir()
    committed = {
        path.stem: path.read_text(encoding="utf-8")
        for path in sorted(schemas_dir.glob("*.json"))
    }

    stale = stale_schemas(committed, generated)
    assert stale == [], (
        f"stale or unmatched schemas: {', '.join(stale)}. "
        f"Regenerate with: {REGENERATE}, then commit {schemas_dir}/*.json"
    )


def test_a_planted_stale_byte_is_reported(tmp_path: Path) -> None:
    """Must-flag control: the comparison sees one changed byte and one missing file."""
    generated = {
        "AshConfig": json.dumps({"title": "AshConfig"}, indent=2) + "\n",
        "Extra": json.dumps({"title": "Extra"}, indent=2) + "\n",
    }
    committed_dir = tmp_path / "schemas"
    committed_dir.mkdir()
    (committed_dir / "AshConfig.json").write_text(
        generated["AshConfig"].replace("AshConfig", "AshConfiG"), encoding="utf-8"
    )
    committed = {
        path.stem: path.read_text(encoding="utf-8")
        for path in sorted(committed_dir.glob("*.json"))
    }

    assert stale_schemas(committed, generated) == ["AshConfig", "Extra"]


def test_matching_text_is_not_reported() -> None:
    """Must-not-flag control for the comparison."""
    text = json.dumps({"title": "AshConfig"}, indent=2) + "\n"

    assert stale_schemas({"AshConfig": text}, {"AshConfig": text}) == []
