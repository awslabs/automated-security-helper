# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash merge --output-formats`` supplies ``output_formats`` a shard recorded as a reference.

A results file records a value its scan read from the environment as the
reference the file wrote, and ``output_formats`` cannot hold one, so the shard's
record lists it as unreadable. ``ash merge`` takes such a field from the
operator or refuses, exit 3 (``supply_unread_recorded_fields``). The operator's
own ``--output-formats`` flag names the formats for the merge, so it supplies the
field as ``--config-overrides 'output_formats=[...]'`` does: the merge runs and
each shard's record holds the flag's formats. Before, only ``--config`` and
``--config-overrides`` were read, and the merge was refused with the flag given.
The flag supplies that field alone, and a flag that is not given supplies nothing.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.cli.merge import (
    stamp_shard_assignment,
    supply_unread_recorded_fields,
)
from automated_security_helper.config.ash_config import (
    AshConfig,
    resolve_env_references,
)
from automated_security_helper.config.recorded_config import unreadable_references
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
OTHER_FIELD = "global_settings.severity_threshold"
OTHER_REFERENCE = "${ASH_PROBE_SEV:LOW}"
RESULTS = "ash_aggregated_results.json"
SCANNERS = ("bandit", "semgrep")
# The variables' value where the merge runs. It reads none of them, so it
# appears in nothing the merge prints.
CANARY = "ash-canary-7f3e-0123456789"
REFUSAL_START = "The configuration recorded in these results cannot be used as it is:"
REFUSAL_END = (
    r"or a --config file that sets it\."
    r"(?: Supply each of the other fields named the same way\.)?"
)


def _record(index: int, count: int, **recorded: str) -> str:
    """Shard *index* of *count*, as a scan whose config read the fields of
    *recorded* from the environment writes it. A key is a field of the record;
    ``global_settings`` is spelled ``global_settings.severity_threshold``."""
    scanner = SCANNERS[index]
    model = AshAggregatedResults()
    model.ash_config = AshConfig(project_name="demo")
    model.scanner_results[scanner] = ScannerStatusInfo(
        status=ScannerStatus.PASSED, excluded=False, dependencies_satisfied=True
    )
    stamp_shard_assignment(
        model,
        ShardAssignment(
            shard_index=index, shard_count=count, assigned_scanners=[scanner]
        ),
    )
    data = json.loads(model.model_dump_json(by_alias=True))
    for field, reference in recorded.items():
        node = data["ash_config"]
        *parents, leaf = field.split(".")
        for key in parents:
            node = node[key]
        node[leaf] = reference
    return json.dumps(data)


@pytest.fixture
def shards(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The directory holding ``shard0`` and ``shard1``, written by each test."""
    for name in ("ASH_PROBE_FORMATS", "ASH_PROBE_SEV"):
        monkeypatch.setenv(name, CANARY)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    # Control: a reference does resolve to the canary in this process.
    assert resolve_env_references(REFERENCE) == CANARY
    for name in ("shard0", "shard1"):
        (tmp_path / name).mkdir()
    return tmp_path


def _write(shards: Path, index: int, **recorded: str) -> Path:
    directory = shards / f"shard{index}"
    (directory / RESULTS).write_text(_record(index, 2, **recorded), encoding="utf-8")
    return directory


def _merge(shards: Path, *extra: str):
    arguments = ["merge", "--output-dir", "merged"]
    for index in (0, 1):
        arguments += ["--results", str(shards / f"shard{index}")]
    return CliRunner().invoke(app, [*arguments, *extra], env={"COLUMNS": "300"})


def _plain(result) -> str:
    """What the command printed with box-drawing characters turned into spaces and
    whitespace collapsed, so a phrase wrapped across lines reads as one."""
    text = re.sub(r"[─-╿]", " ", f"{result.stdout} {result.stderr}")
    return " ".join(text.split())


def _refusal(result) -> str:
    """The merge's refusal alone, from the sentence it begins with to the last
    sentence it ends with. A shard that records a reference raises a log warning
    as it loads, before the flag is read, and that warning names the field even
    when the operator supplies it; the checks read the refusal and not that."""
    match = re.search(f"{re.escape(REFUSAL_START)}.*?{REFUSAL_END}", _plain(result))
    assert match, _plain(result)
    return match.group(0)


def _loaded(shards: Path, index: int) -> AshAggregatedResults:
    return AshAggregatedResults.model_validate_json(
        (shards / f"shard{index}" / RESULTS).read_text("utf-8")
    )


def _formats(results: AshAggregatedResults) -> list:
    return [
        getattr(entry, "value", entry) for entry in results.ash_config.output_formats
    ]


def test_the_shards_record_output_formats_as_a_reference(shards):
    """The control for the tests below: both shards' records list the field as
    unreadable, so the merge needs the operator to supply it."""
    _write(shards, 0, **{FIELD: REFERENCE})
    _write(shards, 1, **{FIELD: REFERENCE})
    for index in (0, 1):
        listed = unreadable_references(_loaded(shards, index).ash_config)
        assert [field for field, _ in listed] == [FIELD]


def test_the_merge_without_the_flag_is_still_refused(shards):
    """The control: with no flag, no override and no file that sets the field,
    the merge is refused, naming the field and the reference and no value."""
    _write(shards, 0, **{FIELD: REFERENCE})
    _write(shards, 1, **{FIELD: REFERENCE})
    result = _merge(shards)
    refusal = _refusal(result)
    assert result.exit_code == 3, _plain(result)
    assert FIELD in refusal and REFERENCE in refusal, refusal
    assert CANARY[:12] not in re.sub(r"[\s─-╿]", "", f"{result.stdout}{result.stderr}")
    assert not (Path("merged") / RESULTS).exists()


def test_the_flag_supplies_output_formats_the_shards_recorded_as_a_reference(shards):
    """The operator chose the formats on the command line, so the merge is not
    refused for the field and writes its merged results."""
    _write(shards, 0, **{FIELD: REFERENCE})
    _write(shards, 1, **{FIELD: REFERENCE})
    result = _merge(shards, "--output-formats", "sarif")
    printed = _plain(result)
    assert REFUSAL_START not in printed, printed
    assert result.exit_code != 3, printed
    assert (Path("merged") / RESULTS).exists(), printed


def test_the_flag_supplies_only_the_field_it_names(shards):
    """A second field the shards recorded as a reference is still refused, and
    the refusal names it and not output_formats."""
    _write(shards, 0, **{OTHER_FIELD: OTHER_REFERENCE})
    _write(shards, 1, **{FIELD: REFERENCE})
    result = _merge(shards, "--output-formats", "sarif")
    refusal = _refusal(result)
    assert result.exit_code == 3, _plain(result)
    assert OTHER_FIELD in refusal and OTHER_REFERENCE in refusal, refusal
    assert FIELD not in refusal and REFERENCE not in refusal, refusal
    assert not (Path("merged") / RESULTS).exists()


@pytest.fixture
def loaded(shards):
    """Both shards' results as the merge reads them, each recording
    output_formats as a reference."""
    _write(shards, 0, **{FIELD: REFERENCE})
    _write(shards, 1, **{FIELD: REFERENCE})
    return [
        (Path(f"shard{index}") / RESULTS, _loaded(shards, index)) for index in (0, 1)
    ]


def test_each_shards_record_takes_the_formats_the_flag_gave(loaded):
    """The value is recorded on every shard's configuration, as a list of the
    field's own type, and each shard holds a list of its own."""
    supply_unread_recorded_fields(
        loaded, AshConfig(project_name="demo"), [], {FIELD: ["sarif", "markdown"]}
    )
    (_, first), (_, second) = loaded
    assert _formats(first) == _formats(second) == ["sarif", "markdown"]
    assert first.ash_config.output_formats is not second.ash_config.output_formats


def test_the_flag_wins_over_an_override_of_the_same_field(loaded):
    """The flag is read after the overrides and replaces the list they gave the
    operator's configuration, as it replaces the list the merge reports with."""
    supply_unread_recorded_fields(
        loaded,
        AshConfig(project_name="demo"),
        ['output_formats=["markdown"]'],
        {FIELD: ["sarif"]},
    )
    (_, first), (_, second) = loaded
    assert _formats(first) == _formats(second) == ["sarif"]


@pytest.mark.parametrize("given", [None, []], ids=["not-given", "empty"])
def test_a_flag_that_gives_no_formats_supplies_nothing(loaded, given):
    """``None`` is a flag the command line did not have, and an empty list names
    no formats; neither supplies the field."""
    with pytest.raises(ASHConfigValidationError, match=FIELD) as raised:
        supply_unread_recorded_fields(
            loaded, AshConfig(project_name="demo"), [], {FIELD: given}
        )
    assert REFERENCE in str(raised.value)
    assert _formats(loaded[0][1]) == []
