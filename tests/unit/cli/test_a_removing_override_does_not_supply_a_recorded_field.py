"""A removing override does not supply a field the record could not read.

``ash merge`` and ``ash report`` refuse a recorded field they cannot read unless
this invocation's operator supplies it (config/recorded_config.py,
take_own_values). A field that holds a list, such as ``output_formats``, is
recorded as a reference when the scan read it from the environment, and the
reference tells nothing about the list the scan used. ``--config-overrides
'output_formats-=["sarif"]'`` takes items out of whatever list the operator's
configuration holds, as ``+=`` adds to it, so it supplies the field no more than an
append does. These tests pin both ways a removal could count as supplying it: the
key ``ash report`` reads from each override (``override.partition("=")[0].strip()``)
names no field, and the record ``apply_config_overrides`` stamps of the fields the
overrides wrote leaves a removal out, as it leaves an append out. A file that
writes the list still supplies it, and the record takes the list as the removal
left it.
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
#: Two formats added to the field's empty default, then one taken out: the
#: run's own configuration refuses a removal from an empty ``output_formats``
#: (an empty list means every enabled reporter's format), so the removal here
#: takes an item out of a list an override wrote.
ADD = 'output_formats+=["sarif", "markdown"]'
REMOVE = 'output_formats-=["sarif"]'
RESULTS = "ash_aggregated_results.json"
# The variable's value where merge and report run. Neither reads it, so it
# appears in nothing they print or raise.
CANARY = "ash-canary-4d1b-9876543210"


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


def _report_keys(*overrides: str) -> list:
    """The override keys ``ash report`` hands to take_own_values, read from each
    override as report.py reads them."""
    return [override.partition("=")[0].strip() for override in overrides]


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


def test_the_key_report_reads_from_a_removal_names_no_field(isolated):
    """Control for report.py's key read, which takes the key as written: the key of a
    ``-=`` keeps its trailing ``-``, which names no field, so the override does not
    supply the field by its key, and the operator's configuration, which does not
    write it, does not supply it either."""
    own = _own_config(isolated, "project_name: demo\n")
    record = _loaded_record()
    with pytest.raises(ASHConfigValidationError, match=FIELD) as raised:
        _take(record, own, override_keys=_report_keys(REMOVE))
    assert REFERENCE in str(raised.value)
    _assert_no_value(str(raised.value))
    assert _formats(record) == []


def test_a_removing_override_does_not_write_the_field(isolated):
    """The removal changed the list the operator's configuration holds, and the
    file never wrote the field, so the written-field record does not hold it."""
    own = _own_config(isolated, "project_name: demo\n")
    rebuilt = apply_config_overrides(own, [ADD, REMOVE])
    # The control: the removal applied.
    assert _formats(rebuilt) == ["markdown"]
    assert rebuilt._written_before_overrides is not None
    assert FIELD not in rebuilt._written_before_overrides
    assert not _sets(rebuilt, [FIELD])


def test_a_removing_override_does_not_supply_the_field(isolated):
    """Report's and merge's check: the removal leaves the field unsupplied, so
    the refusal holds and names the field and the reference, never a value, and
    the record keeps the default it was read with."""
    own = _own_config(isolated, "project_name: demo\n")
    rebuilt = apply_config_overrides(own, [ADD, REMOVE])
    record = _loaded_record()
    with pytest.raises(ASHConfigValidationError, match=FIELD) as raised:
        _take(record, rebuilt, override_keys=_report_keys(ADD, REMOVE))
    assert REFERENCE in str(raised.value)
    _assert_no_value(str(raised.value))
    assert _formats(record) == []


def test_a_removal_from_a_list_the_file_wrote_still_supplies_it(isolated):
    """The control on the other side: the operator's file wrote the list, so the
    field was supplied before the removal, the removal unwrites nothing, and the
    record takes the list the removal left."""
    own = _own_config(
        isolated, "project_name: demo\noutput_formats:\n  - markdown\n  - sarif\n"
    )
    rebuilt = apply_config_overrides(own, [REMOVE])
    record = _loaded_record()
    _take(record, rebuilt)
    assert _formats(record) == ["markdown"]


@pytest.fixture
def shard(isolated: Path) -> Path:
    directory = isolated / "shard0"
    directory.mkdir()
    (directory / RESULTS).write_text(_record(), encoding="utf-8")
    return directory


def test_report_refuses_under_a_removing_override(shard):
    """The report takes the field from its own configuration, which the two
    overrides change without writing the field, so it refuses in the wording an
    append gets instead of reporting under the list the removal left."""
    result = CliRunner().invoke(
        app,
        [
            "report",
            "--format",
            "markdown",
            "--output-dir",
            str(shard),
            "--config-overrides",
            ADD,
            "--config-overrides",
            REMOVE,
        ],
        env={"COLUMNS": "300"},
    )
    printed = _plain(result)
    assert result.exit_code == 3, printed
    assert FIELD in printed and REFERENCE in printed, printed
    assert "does not supply the field" in printed, printed
    _assert_no_value(f"{result.stdout}\n{result.stderr}")
