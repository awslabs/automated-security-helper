# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An override that appends to a list does not supply a field the record could not read.

``ash merge`` and ``ash report`` refuse a recorded field they cannot read unless
this invocation's operator supplies it (config/recorded_config.py,
take_own_values). A field that holds a list, such as ``output_formats``, is
recorded as a reference when the scan read it from the environment, and the
reference tells nothing about the list the scan used. ``--config-overrides
'output_formats+=["sarif"]'`` adds one entry to whatever list the operator's
configuration holds, which here is the field's default, so counting it as
supplying the field brought back the default list plus that entry in place of
the refusal. These tests pin that an append supplies nothing, that a replacing
override and a file that writes the field still do, and that the value taken
from the operator is a copy, so one shard's record cannot change another's.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.cli.merge import stamp_shard_assignment
from automated_security_helper.config.ash_config import (
    AshConfig,
    resolve_env_references,
)
from automated_security_helper.config.recorded_config import (
    HOW_TO_SUPPLY,
    _sets,
    take_own_values,
    unreadable_references,
)
from automated_security_helper.config.resolve_config import (
    apply_config_overrides,
    resolve_config,
)
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.core.sharding import ShardAssignment
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerStatusInfo,
)

pytestmark = pytest.mark.unit

FIELD = "output_formats"
REFERENCE = "${ASH_PROBE_FORMATS}"
APPEND = 'output_formats+=["sarif"]'
REPLACE = 'output_formats=["sarif"]'
RESULTS = "ash_aggregated_results.json"
# The variable's value where merge and report run. Neither reads it, so it
# appears in nothing they print or raise.
CANARY = "ash-canary-7f3e-0123456789"


def _assert_no_value(text: str) -> None:
    """Whitespace and box-drawing characters removed, so a value wrapped across
    lines or a panel border still counts; and its leading part, so a truncated
    one does too."""
    squeezed = re.sub(r"[\s─-╿]", "", text)
    assert CANARY not in squeezed and CANARY[:12] not in squeezed, text


def _plain(result) -> str:
    """What the command printed with box-drawing characters turned into spaces and
    whitespace collapsed, so a phrase wrapped across lines reads as one."""
    text = re.sub(r"[─-╿]", " ", f"{result.stdout} {result.stderr}")
    return " ".join(text.split())


def _record() -> str:
    """One shard's results, as a scan whose config read output_formats from the
    environment writes them."""
    model = AshAggregatedResults()
    model.ash_config = AshConfig(project_name="demo")
    model.scanner_results["bandit"] = ScannerStatusInfo(
        status=ScannerStatus.PASSED, excluded=False, dependencies_satisfied=True
    )
    stamp_shard_assignment(
        model,
        ShardAssignment(shard_index=0, shard_count=1, assigned_scanners=["bandit"]),
    )
    data = json.loads(model.model_dump_json(by_alias=True))
    data["ash_config"][FIELD] = REFERENCE
    return json.dumps(data)


def _loaded_record() -> AshConfig:
    """The record as merge and report read it: output_formats unreadable."""
    return AshAggregatedResults.model_validate_json(_record()).ash_config


def _formats(config: AshConfig) -> list:
    return [getattr(entry, "value", entry) for entry in config.output_formats]


@pytest.fixture
def isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("ASH_PROBE_FORMATS", CANARY)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    # Control: the reference does resolve to the canary in this process.
    assert resolve_env_references(REFERENCE) == CANARY
    return tmp_path


def _own_config(directory: Path, text: str) -> AshConfig:
    path = directory / "own.yaml"
    path.write_text(text, encoding="utf-8")
    return resolve_config(config_path=path, fallback_to_default=False)


def _take(record: AshConfig, own: AshConfig, **kwargs) -> None:
    take_own_values(record, own, refuse_unless_supplied=HOW_TO_SUPPLY, **kwargs)


def test_the_record_lists_the_field_as_unreadable(isolated):
    """The control for every test here: the record's output_formats is a
    reference the field cannot hold, so it is listed for the operator to supply."""
    listed = unreadable_references(_loaded_record())
    assert [field for field, _ in listed] == [FIELD]


def test_an_appending_override_does_not_write_the_field(isolated):
    """The append changed the list the operator's configuration holds, and the
    file never wrote the field, so the written-field record does not hold it."""
    own = _own_config(isolated, "project_name: demo\n")
    rebuilt = apply_config_overrides(own, [APPEND])
    # The control: the append applied.
    assert _formats(rebuilt) == ["sarif"]
    assert rebuilt._written_before_overrides is not None
    assert FIELD not in rebuilt._written_before_overrides
    assert not _sets(rebuilt, [FIELD])


def test_an_appending_override_does_not_supply_the_field(isolated):
    """Report's and merge's check: the append leaves the field unsupplied, so
    the refusal holds and names the field and the reference, never a value, and
    the record keeps the default it was read with."""
    own = _own_config(isolated, "project_name: demo\n")
    rebuilt = apply_config_overrides(own, [APPEND])
    record = _loaded_record()
    with pytest.raises(ASHConfigValidationError, match=FIELD) as raised:
        _take(record, rebuilt, override_keys=[APPEND.partition("=")[0].strip()])
    assert REFERENCE in str(raised.value)
    _assert_no_value(str(raised.value))
    assert _formats(record) == []


def test_the_refusal_says_an_append_does_not_supply_the_field(isolated):
    own = _own_config(isolated, "project_name: demo\n")
    rebuilt = apply_config_overrides(own, [APPEND])
    with pytest.raises(ASHConfigValidationError) as raised:
        _take(_loaded_record(), rebuilt)
    text = " ".join(str(raised.value).split())
    assert f"--config-overrides '{FIELD}=<value>'" in text, text
    assert "'+=' adds to a value and does not supply the field" in text, text


def test_a_replacing_override_still_supplies_the_field(isolated):
    """The control: the same value written with = is a full value, so the field
    is supplied and the record takes it."""
    own = _own_config(isolated, "project_name: demo\n")
    rebuilt = apply_config_overrides(own, [REPLACE])
    record = _loaded_record()
    _take(record, rebuilt)
    assert _formats(record) == ["sarif"]


def test_an_append_to_a_list_the_file_wrote_still_supplies_it(isolated):
    """The control: the operator's file wrote the list, so the field was supplied
    before the append, and the append adds to the list the operator chose."""
    own = _own_config(isolated, "project_name: demo\noutput_formats:\n  - markdown\n")
    rebuilt = apply_config_overrides(own, [APPEND])
    record = _loaded_record()
    _take(record, rebuilt)
    assert _formats(record) == ["markdown", "sarif"]


@pytest.fixture
def shard(isolated: Path) -> Path:
    directory = isolated / "shard0"
    directory.mkdir()
    (directory / RESULTS).write_text(_record(), encoding="utf-8")
    return directory


def test_merge_refuses_under_an_appending_override(shard):
    """The merge applies the override to the shard's record and to the operator's
    configuration; neither supplies the field, so it is refused and nothing is
    merged. Before, the merged report was written with the default list plus the
    appended entry."""
    result = CliRunner().invoke(
        app,
        [
            "merge",
            "--results",
            str(shard),
            "--output-dir",
            "merged",
            "--config-overrides",
            APPEND,
        ],
        env={"COLUMNS": "300"},
    )
    printed = _plain(result)
    assert result.exit_code == 3, printed
    assert FIELD in printed and REFERENCE in printed, printed
    assert "does not supply the field" in printed, printed
    _assert_no_value(f"{result.stdout}\n{result.stderr}")
    assert not (Path("merged") / RESULTS).exists()


def test_report_refuses_under_an_appending_override(shard):
    """The report takes the same field from the same configuration and refuses
    in the same wording, instead of reporting under the default list plus the
    appended entry."""
    result = CliRunner().invoke(
        app,
        [
            "report",
            "--format",
            "markdown",
            "--output-dir",
            str(shard),
            "--config-overrides",
            APPEND,
        ],
        env={"COLUMNS": "300"},
    )
    printed = _plain(result)
    assert result.exit_code == 3, printed
    assert FIELD in printed and REFERENCE in printed, printed
    assert "does not supply the field" in printed, printed
    _assert_no_value(f"{result.stdout}\n{result.stderr}")


def test_each_record_takes_its_own_copy_of_the_operators_list(isolated):
    """The value taken from the operator is a copy: two shards' records and the
    operator's configuration hold three lists, so a change to one shard's list in
    place reaches neither the operator's nor the other shard's."""
    own = _own_config(isolated, "project_name: demo\noutput_formats:\n  - sarif\n")
    first, second = _loaded_record(), _loaded_record()
    for record in (first, second):
        _take(record, own)
    # The control: both took the operator's list.
    assert _formats(first) == _formats(second) == _formats(own) == ["sarif"]
    assert first.output_formats is not own.output_formats
    assert second.output_formats is not own.output_formats
    assert first.output_formats is not second.output_formats
    first.output_formats.append("markdown")
    assert _formats(own) == ["sarif"]
    assert _formats(second) == ["sarif"]
    assert _formats(first) == ["sarif", "markdown"]
