# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which fields the operator supplies, around ``--config-overrides``.

``ash merge`` and ``ash report`` refuse a recorded field they cannot read
unless this invocation's operator supplies it (config/recorded_config.py,
take_own_values). The operator supplies a field by writing it in the
configuration file, at any value, the default included, or by naming it in
``--config-overrides``, whatever the value. Applying overrides changes that
set only by the keys the overrides name: an override of one field says
nothing about any other.

The supplied check reads ``model_fields_set``, which a freshly parsed file
holds exactly as written. ``apply_config_overrides`` rebuilds the model from
a full dump, and these cells pin that the rebuild does not widen the
supplied set.
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
from automated_security_helper.config.config_writer import render_config_file
from automated_security_helper.config.recorded_config import (
    HOW_TO_SUPPLY,
    take_own_values,
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

REFERENCE = "${ASH_PROBE_SEV:LOW}"
FIELD = "global_settings.severity_threshold"
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


def _record() -> str:
    """One shard's results, as a scan whose config read severity_threshold from
    the environment writes them."""
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
    data["ash_config"]["global_settings"]["severity_threshold"] = REFERENCE
    return json.dumps(data)


def _loaded_record() -> AshConfig:
    """The record as merge and report read it: severity_threshold unreadable."""
    return AshAggregatedResults.model_validate_json(_record()).ash_config


@pytest.fixture
def isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("ASH_PROBE_SEV", CANARY)
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


def test_a_file_that_writes_the_default_supplies_it_through_an_override(isolated):
    """An operator who wrote severity_threshold: MEDIUM chose MEDIUM, the
    default or not; an unrelated override does not unchoose it."""
    own = _own_config(
        isolated,
        "project_name: demo\nglobal_settings:\n  severity_threshold: MEDIUM\n",
    )
    rebuilt = apply_config_overrides(own, ["project_name=other"])
    record = _loaded_record()
    _take(record, rebuilt)
    assert record.global_settings.severity_threshold == "MEDIUM"


def test_an_override_naming_the_field_supplies_it(isolated):
    """Report's shape: the override keys it was passed name the field."""
    own = _own_config(isolated, "project_name: demo\n")
    rebuilt = apply_config_overrides(own, [f"{FIELD}=HIGH"])
    record = _loaded_record()
    _take(record, rebuilt, override_keys=[FIELD])
    assert record.global_settings.severity_threshold == "HIGH"


def test_an_applied_override_supplies_its_field_without_the_keys_argument(isolated):
    """The rebuilt configuration itself remembers which keys its overrides
    named: a caller that applied them but passes no override_keys still
    counts the named field supplied, and the override's value is the one
    taken."""
    own = _own_config(isolated, "project_name: demo\n")
    rebuilt = apply_config_overrides(own, [f"{FIELD}=HIGH"])
    record = _loaded_record()
    _take(record, rebuilt)
    assert record.global_settings.severity_threshold == "HIGH"


def test_an_override_spelled_as_a_fold_is_recorded_as_the_key_it_wrote(isolated):
    """The apply folds a spelling of a declared plugin's section to the key
    the document holds, so the override lands; the record spells it the same
    way, so the field counts written under the spellings a reader asks with.
    Recording the key as typed brought back a refusal against an operator
    whose override did apply."""
    from automated_security_helper.config.recorded_config import _sets

    own = _own_config(isolated, "project_name: demo\n")
    rebuilt = apply_config_overrides(own, ["scanners.CdkNag.enabled=false"])
    # The control: the folded spelling applied.
    assert rebuilt.scanners.cdk_nag.enabled is False
    assert _sets(rebuilt, ["scanners", "cdk-nag", "enabled"])
    assert _sets(rebuilt, ["scanners", "cdk_nag", "enabled"])


def test_a_mapping_override_supplies_the_fields_inside_its_value(isolated):
    """An override whose value is a mapping writes every field inside it: the
    record takes the parsed value's paths, so the field counts supplied and
    the override's value is taken, not refused."""
    own = _own_config(isolated, "project_name: demo\n")
    rebuilt = apply_config_overrides(
        own, ['global_settings={"severity_threshold":"HIGH"}']
    )
    record = _loaded_record()
    _take(record, rebuilt)
    assert record.global_settings.severity_threshold == "HIGH"


def test_a_mapping_override_unwrites_the_fields_it_replaces(isolated):
    """A replacing override overwrote the whole subtree under its key: a
    field the file wrote there and the value does not hold is gone, holding
    its default, so the record no longer counts it written and the refusal
    holds. Keeping the file's entry reported under the default the scan
    never chose, in silence."""
    own = _own_config(
        isolated,
        "project_name: demo\nglobal_settings:\n  severity_threshold: HIGH\n",
    )
    rebuilt = apply_config_overrides(own, ['global_settings={"ignore_paths":[]}'])
    assert rebuilt.global_settings.severity_threshold == "MEDIUM"
    with pytest.raises(ASHConfigValidationError, match="severity_threshold") as raised:
        _take(_loaded_record(), rebuilt)
    _assert_no_value(str(raised.value))


def test_an_extra_section_named_like_a_model_attribute_is_recorded(isolated):
    """A plugin section is an extra key, read through model_extra; one named
    like a BaseModel attribute ("json") must record what the file wrote under
    it the same way a plainly named one does, so a written field survives the
    rebuild's record."""
    from automated_security_helper.config.recorded_config import _sets

    own = _own_config(
        isolated,
        "project_name: demo\n"
        "scanners:\n"
        "  json:\n    enabled: true\n"
        "  plainname:\n    enabled: true\n",
    )
    rebuilt = apply_config_overrides(own, ["project_name=other"])
    # The control: a plainly named extra section records.
    assert _sets(rebuilt, ["scanners", "plainname", "enabled"])
    assert _sets(rebuilt, ["scanners", "json", "enabled"])


def test_an_override_set_to_the_fields_default_still_supplies_it(isolated):
    """Naming the field is supplying it, whatever the value: the override
    membership check comes before any comparison with the default."""
    own = _own_config(isolated, "project_name: demo\n")
    rebuilt = apply_config_overrides(own, [f"{FIELD}=MEDIUM"])
    record = _loaded_record()
    _take(record, rebuilt, override_keys=[FIELD])
    assert record.global_settings.severity_threshold == "MEDIUM"


def test_an_unrelated_override_does_not_supply_an_unwritten_field(isolated):
    """The root defect's cell: the file does not write the field and the only
    override names another key, so the field stays unsupplied and the refusal
    holds. apply_config_overrides rebuilds the model from a full dump, which
    marks every field written; without a record of the pre-rebuild written
    set, this refusal vanished under any unrelated override."""
    own = _own_config(isolated, "project_name: demo\n")
    rebuilt = apply_config_overrides(own, ["project_name=other"])
    with pytest.raises(ASHConfigValidationError, match="severity_threshold") as raised:
        _take(_loaded_record(), rebuilt)
    _assert_no_value(str(raised.value))


def test_the_first_applications_record_survives_a_second_application(isolated):
    """resolve_config applies overrides more than once to one model (the
    reporter fold applies onto the trusted base after the first application):
    the second rebuild keeps the first's record, which the first rebuild's
    widened model_fields_set can no longer reproduce."""
    own = _own_config(isolated, "project_name: demo\n")
    once = apply_config_overrides(own, ["project_name=a"])
    twice = apply_config_overrides(once, ["project_name=b"])
    with pytest.raises(ASHConfigValidationError, match="severity_threshold"):
        _take(_loaded_record(), twice)
    # The carried record: the first application's paths survive the second,
    # and the unwritten field never joins them.
    assert once._written_before_overrides is not None
    assert once._written_before_overrides <= twice._written_before_overrides
    assert "project_name" in twice._written_before_overrides
    assert FIELD not in twice._written_before_overrides


def test_a_field_mutated_after_the_resolve_is_invisible_to_the_record(isolated):
    """The record-based read's known constraint, pinned: the record is
    stamped when the overrides are applied and never re-derived, so a field
    assigned on the resolved model afterwards diverges from it silently --
    the read keeps answering from the record. Nothing in the resolve-to-read
    window mutates a resolved config today, which is what keeps the record
    current. Whoever makes this cell fail has introduced such a mutation,
    and with it the duty to refresh or invalidate the record (the comment at
    the record read says the same)."""
    from automated_security_helper.config.recorded_config import _sets

    own = _own_config(isolated, "project_name: demo\n")
    rebuilt = apply_config_overrides(own, ["project_name=other"])
    # Control: the record exists and holds what the file wrote.
    assert rebuilt._written_before_overrides is not None
    assert not _sets(rebuilt, ["global_settings", "severity_threshold"])
    # The mutation is live on the model...
    rebuilt.global_settings.severity_threshold = "CRITICAL"
    assert rebuilt.global_settings.severity_threshold == "CRITICAL"
    # ...and the resolved segments now differ from the record: the read
    # still answers from the record, not from the mutated model.
    assert not _sets(rebuilt, ["global_settings", "severity_threshold"])
    assert FIELD not in rebuilt._written_before_overrides


def test_no_file_entry_and_no_override_refuses(isolated):
    """The field is unsupplied: the file does not write it and no override
    names it, so the refusal holds and names the field."""
    own = _own_config(isolated, "project_name: demo\n")
    with pytest.raises(ASHConfigValidationError, match="severity_threshold"):
        _take(_loaded_record(), own)


def test_a_fresh_load_with_no_overrides_supplies_what_the_file_writes(isolated):
    """No overrides were ever applied: the file's own written set answers."""
    own = _own_config(
        isolated,
        "project_name: demo\nglobal_settings:\n  severity_threshold: HIGH\n",
    )
    record = _loaded_record()
    _take(record, own)
    assert record.global_settings.severity_threshold == "HIGH"


def test_an_ash_written_config_supplies_every_field(isolated):
    """ASH's own config writers (init, update, wizard, the MCP session config)
    serialize every default, so a config they wrote supplies every field it
    holds, severity_threshold included, through any override."""
    path = isolated / "ash-written.yaml"
    path.write_text(
        render_config_file(path, AshConfig(project_name="demo"), comments=[]),
        encoding="utf-8",
    )
    own = resolve_config(config_path=path, fallback_to_default=False)
    rebuilt = apply_config_overrides(own, ["project_name=other"])
    record = _loaded_record()
    _take(record, rebuilt)
    assert record.global_settings.severity_threshold == "MEDIUM"


@pytest.fixture
def shard(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("ASH_PROBE_SEV", CANARY)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    directory = tmp_path / "shard0"
    directory.mkdir()
    (directory / RESULTS).write_text(_record(), encoding="utf-8")
    return directory


def _report(shard: Path, *extra: str):
    return CliRunner().invoke(
        app,
        ["report", "--format", "markdown", "--output-dir", str(shard), *extra],
        env={"COLUMNS": "300"},
    )


def test_report_refuses_under_an_unrelated_override(shard):
    """ash report passes --config-overrides into resolve_config before the
    supplied check runs, so the rebuild is live on this path: one override
    naming another key does not supply severity_threshold, and the refusal
    holds exactly as it does with no overrides at all."""
    result = _report(shard, "--config-overrides", "project_name=other")
    printed = " ".join(f"{result.stdout} {result.stderr}".split())
    assert result.exit_code == 3, printed
    assert FIELD in printed and REFERENCE in printed, printed
    assert "--config-overrides" in printed, printed
    _assert_no_value(f"{result.stdout}\n{result.stderr}")


def test_report_with_an_unrelated_override_proceeds_once_the_field_is_supplied(shard):
    """The control for the refusal cell beside it: with the field supplied,
    the unrelated override is no obstacle either."""
    result = _report(
        shard,
        "--config-overrides",
        "project_name=other",
        "--config-overrides",
        f"{FIELD}=HIGH",
    )
    assert result.exit_code == 0, result.output
    _assert_no_value(f"{result.stdout}\n{result.stderr}")
    assert "HIGH (global)" in result.stdout, result.stdout


def test_merge_refuses_though_the_operator_config_sets_other_fields(shard, tmp_path):
    """merge's supplied set is the --config file's written fields and the keys
    of its --config-overrides; a file that writes other fields does not supply
    this one."""
    operator = tmp_path / "operator.yaml"
    operator.write_text("project_name: operator\n", encoding="utf-8")
    result = CliRunner().invoke(
        app,
        [
            "merge",
            "--results",
            str(shard),
            "--output-dir",
            "merged",
            "--config",
            str(operator),
        ],
        env={"COLUMNS": "300"},
    )
    printed = " ".join(f"{result.stdout} {result.stderr}".split())
    assert result.exit_code == 3, printed
    assert FIELD in printed and REFERENCE in printed, printed
    _assert_no_value(f"{result.stdout}\n{result.stderr}")
    assert not (Path("merged") / RESULTS).exists()
