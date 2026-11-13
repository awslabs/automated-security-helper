# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A name that is not UTF-8 in the configuration is written as text and read back as itself.

The result models hold such a name in its record form, the six characters ``\\udcNN``
(utils/undecodable_text.py). The live configuration is not a record model: the scan
matches files against it, so it keeps the name it read, and its record in the
results file is written in the form from a copy. A run that reads the results back
(``ash report``, ``--use-existing``, ``ash merge``) reads the form back as the name,
so it applies the ignore paths and suppressions the scan applied.

A dump that meets a lone surrogate a model got after it was built is written again
in the form; a dump that fails for any other reason raises its own error.
"""

from __future__ import annotations

import json
import os

import pytest
from pydantic_core import PydanticSerializationError

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import PropertyBag
from tests.unit.cli import test_merge

pytestmark = pytest.mark.unit

# The constant below is a file name that is not UTF-8.
if os.name == "nt":
    pytest.skip(
        "a file name that is not UTF-8 cannot exist on NTFS (names are UTF-16)",
        allow_module_level=True,
    )

#: A latin-1 file name as Python lists it, and as a record writes it.
ODD = os.fsdecode(b"secr\xe9t.py")
RECORDED = "secr\\udce9t.py"


def _config() -> AshConfig:
    return AshConfig(
        global_settings={
            "ignore_paths": [{"path": ODD, "reason": "generated"}],
            "suppressions": [{"path": "app.py", "rule_id": "R1", "reason": ODD}],
        }
    )


def test_the_live_configuration_keeps_the_name_it_read():
    config = _config()
    before = config.model_dump()

    results = AshAggregatedResults(ash_config=config)
    written = results.model_dump_json()

    assert config.model_dump() == before
    assert config.global_settings.ignore_paths[0].path == ODD
    assert results.ash_config.global_settings.ignore_paths[0].path == ODD
    recorded = json.loads(written)["ash_config"]["global_settings"]
    assert recorded["ignore_paths"][0]["path"] == RECORDED
    assert recorded["suppressions"][0]["reason"] == RECORDED


def test_the_recorded_configuration_reads_back_as_the_name():
    written = AshAggregatedResults(ash_config=_config()).model_dump_json()

    read_back = AshAggregatedResults.model_validate_json(written)

    settings = read_back.ash_config.global_settings
    assert settings.ignore_paths[0].path == ODD
    assert settings.suppressions[0].reason == ODD
    # Written again, it is the same document.
    assert read_back.model_dump_json() == written


def test_ash_merge_keeps_one_name_for_two_shards_that_hold_it(tmp_path):
    shards = test_merge.build_shards(2)
    for shard in shards:
        shard.ash_config = _config()
    paths = test_merge.write_shards(tmp_path / "artifacts", shards)
    output_dir = tmp_path / "merged"
    args = []
    for path in paths:
        args += ["--results", path]

    # The merge test's in-process command, with its SARIF and CSV reporters.
    result = test_merge.TestMergeCli()._invoke(
        args + ["--output-dir", str(output_dir), "--output-formats", "sarif"]
    )

    assert result.exit_code in (0, 2), result.output
    written = (output_dir / "ash_aggregated_results.json").read_text(encoding="utf-8")
    recorded = json.loads(written)["ash_config"]["global_settings"]["ignore_paths"]
    assert [entry["path"] for entry in recorded] == [RECORDED]
    merged = AshAggregatedResults.model_validate_json(written)
    assert [entry.path for entry in merged.ash_config.global_settings.ignore_paths] == [
        ODD
    ]


def test_a_project_name_set_after_the_results_are_built_is_saved(tmp_path):
    """The orchestrator names a workspace project after its directory, assigning it
    to the metadata after the results were validated."""
    results = AshAggregatedResults()
    results.metadata.project_name = os.fsdecode(b"caf\xe9")

    results.save_model(tmp_path)

    saved = json.loads(
        (tmp_path / "ash_aggregated_results.json").read_text(encoding="utf-8")
    )
    assert saved["metadata"]["project_name"] == "caf\\udce9"


def test_the_written_form_takes_the_options_of_the_dump():
    """Only the options model_dump takes reach it; indent and ensure_ascii lay out the
    text as they would without such a name."""
    results = AshAggregatedResults()
    results.metadata.requested_scanners_not_run = [ODD]

    written = results.model_dump_json(
        indent=2, ensure_ascii=True, exclude_none=True, by_alias=True
    )

    assert written.startswith("{\n  ")
    assert written.isascii()
    document = json.loads(written)
    assert document["metadata"]["requested_scanners_not_run"] == [RECORDED]
    assert all(value is not None for value in document["metadata"].values())


#: A lone leading surrogate, and a surrogate pair held as two code points rather than as
#: the one character they would encode. Built with chr() so the source holds no such
#: character.
_LONE_HIGH = "a" + chr(0xD800) + "b.py"
_PAIR = "a" + chr(0xD83D) + chr(0xDE00) + ".py"


@pytest.mark.parametrize(
    "name,recorded",
    [(_LONE_HIGH, "a\\ud800b.py"), (_PAIR, "a\\ud83d\\ude00.py")],
    ids=["lone-leading-surrogate", "pair-held-as-two-code-points"],
)
def test_a_surrogate_outside_the_bytes_of_a_posix_name_is_recorded_and_read_back(
    name, recorded
):
    """A Windows file name can hold any lone surrogate, which UTF-8 cannot write either.
    It is recorded as its escape, read back as the name, and matched in both forms."""
    from automated_security_helper.utils.suppression_matcher import (
        ignore_path_matches,
    )

    config = AshConfig(
        global_settings={"ignore_paths": [{"path": name, "reason": "x"}]}
    )

    written = AshAggregatedResults(ash_config=config).model_dump_json()

    document = json.loads(written)
    assert document["ash_config"]["global_settings"]["ignore_paths"][0]["path"] == (
        recorded
    )
    read_back = AshAggregatedResults.model_validate_json(written)
    # ascii(): a report holding a lone surrogate cannot be sent between workers.
    assert ascii(read_back.ash_config.global_settings.ignore_paths[0].path) == ascii(
        name
    )
    assert read_back.model_dump_json() == written
    assert ignore_path_matches(recorded, name)
    assert ignore_path_matches(name, recorded)


def test_a_dump_that_fails_for_another_reason_raises_its_own_error():
    """Told by what the dump holds, not by the error's words: no lone surrogate,
    no second dump."""
    bag = PropertyBag()
    bag.__pydantic_extra__["opaque"] = object()

    with pytest.raises(PydanticSerializationError):
        bag.model_dump_json()


def test_ash_merge_applies_the_recorded_config_to_a_name_that_is_not_utf8(tmp_path):
    """ash merge applies each shard's recorded suppressions and ignore paths to the
    merged results. The recorded config reads back as the names, the results hold
    them in the record form, and the matcher compares the two in that form."""
    from automated_security_helper.schemas.sarif_schema_model import (
        ArtifactLocation,
        Location,
        Message,
        PhysicalLocation,
        Result,
    )

    ignored = os.fsdecode(b"ign\xe9.py")
    config = AshConfig(
        global_settings={
            "suppressions": [{"path": ODD, "rule_id": "R-ODD", "reason": "x"}],
            "ignore_paths": [{"path": ignored, "reason": "x"}],
        }
    )
    shards = test_merge.build_shards(2)
    for shard in shards:
        shard.ash_config = config
    for rule, name in (("R-ODD", ODD), ("R-IGN", ignored)):
        shards[0].sarif.runs[0].results.append(
            Result(
                ruleId=rule,
                message=Message(text="finding"),
                locations=[
                    Location(
                        physicalLocation=PhysicalLocation(
                            artifactLocation=ArtifactLocation(uri=name)
                        )
                    )
                ],
            )
        )
    paths = test_merge.write_shards(tmp_path / "artifacts", shards)
    output_dir = tmp_path / "merged"
    args = []
    for path in paths:
        args += ["--results", path]

    result = test_merge.TestMergeCli()._invoke(
        args + ["--output-dir", str(output_dir), "--output-formats", "sarif"]
    )

    assert result.exit_code in (0, 2), result.output
    merged = json.loads(
        (output_dir / "ash_aggregated_results.json").read_text(encoding="utf-8")
    )
    by_rule = {
        found["ruleId"]: found
        for run in merged["sarif"]["runs"]
        for found in run.get("results") or []
        if found["ruleId"] in ("R-ODD", "R-IGN")
    }
    assert by_rule["R-ODD"].get("suppressions"), by_rule
    assert "R-IGN" not in by_rule or by_rule["R-IGN"].get("suppressions"), by_rule
