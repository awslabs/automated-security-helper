# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash merge`` and ``ash report`` refuse recorded references in one wording.

A results file records a value its scan read from the environment as the
reference the file wrote, and a fixed-choice field cannot hold one. Both commands
take the field from the operator or refuse, exit 3, with the message
``unsupplied_refusal`` builds (config/recorded_config.py). The wording belongs to
that function and not to a command:

- one reference is "a reference" and the field "cannot hold it";
- several are "references" the fields "cannot hold them";
- when more than one field is named, the refusal sends the operator to supply the
  others the same way.

``ash merge`` used to add that last sentence itself and keep the singular lead-in,
and ``ash report`` had neither, so it refused two fields in the singular.
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
    unsupplied_refusal,
)
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.sharding import ShardAssignment
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerStatusInfo,
)

FIELD = "global_settings.severity_threshold"
REFERENCE = "${ASH_PROBE_SEV:LOW}"
OTHER_FIELD = "output_formats"
OTHER_REFERENCE = "${ASH_PROBE_FORMATS}"
RESULTS = "ash_aggregated_results.json"
# The variables' value where the commands run. Neither reads them, so it appears
# in nothing they print.
CANARY = "ash-canary-7f3e-0123456789"

SINGULAR = (
    "That is a reference read from the environment where the scan ran, which is "
    "not read again here, and the field cannot hold it."
)
PLURAL_FIELDS = (
    "Those are references read from the environment where the scan ran, which are "
    "not read again here, and the fields cannot hold them."
)
PLURAL_ONE_FIELD = (
    "Those are references read from the environment where the scan ran, which are "
    "not read again here, and the field cannot hold them."
)
OTHERS = "Supply each of the other fields named the same way."


def _text(*pairs: tuple[str, str]) -> str:
    named = "; ".join(f"{field} is recorded as {ref}" for field, ref in pairs)
    return str(unsupplied_refusal(named, list(pairs), HOW_TO_SUPPLY))


def test_one_reference_is_refused_in_the_singular():
    text = _text((FIELD, REFERENCE))
    assert SINGULAR in text, text
    assert f"--config-overrides '{FIELD}=<value>'" in text, text
    assert OTHERS not in text, text


def test_a_pair_named_twice_counts_once():
    """Two shards that record the same field as the same reference name one
    reference, so the refusal does not turn plural."""
    text = _text((FIELD, REFERENCE), (FIELD, REFERENCE))
    assert SINGULAR in text, text
    assert PLURAL_FIELDS not in text and PLURAL_ONE_FIELD not in text, text
    assert OTHERS not in text, text


def test_several_fields_are_refused_in_the_plural_and_send_the_operator_on():
    text = _text((FIELD, REFERENCE), (OTHER_FIELD, OTHER_REFERENCE))
    assert PLURAL_FIELDS in text, text
    assert text.count(OTHERS) == 1, text
    assert SINGULAR not in text, text
    # The example in the way to supply names the first field.
    assert f"--config-overrides '{FIELD}=<value>'" in text, text


def test_one_field_with_two_references_is_plural_without_other_fields():
    text = _text((FIELD, REFERENCE), (FIELD, "${ASH_PROBE_SEV_TWO:LOW}"))
    assert PLURAL_ONE_FIELD in text, text
    assert OTHERS not in text, text
    assert SINGULAR not in text, text


def _record(**recorded: str) -> str:
    """One shard's results, as a scan whose config read the fields of *recorded*
    from the environment writes them. A key is a field of the record;
    ``global_settings`` is spelled ``global_settings.severity_threshold``."""
    model = AshAggregatedResults()
    model.ash_config = AshConfig(project_name="demo")
    model.scanner_results["semgrep"] = ScannerStatusInfo(
        status=ScannerStatus.PASSED, excluded=False, dependencies_satisfied=True
    )
    stamp_shard_assignment(
        model,
        ShardAssignment(shard_index=0, shard_count=1, assigned_scanners=["semgrep"]),
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
def shard(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    for name in ("ASH_PROBE_SEV", "ASH_PROBE_FORMATS"):
        monkeypatch.setenv(name, CANARY)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    # Control: a reference does resolve to the canary in this process.
    assert resolve_env_references(REFERENCE) == CANARY
    directory = tmp_path / "shard0"
    directory.mkdir()
    return directory


def _run(command: str, shard: Path):
    if command == "merge":
        arguments = ["merge", "--results", str(shard), "--output-dir", "merged"]
    else:
        arguments = ["report", "--format", "markdown", "--output-dir", str(shard)]
    return CliRunner().invoke(app, arguments, env={"COLUMNS": "300"})


def _plain(result) -> str:
    """What the command printed with box-drawing characters turned into spaces and
    whitespace collapsed, so a phrase wrapped across lines reads as one."""
    text = re.sub(r"[─-╿]", " ", f"{result.stdout} {result.stderr}")
    return " ".join(text.split())


def _assert_no_value(result) -> None:
    squeezed = re.sub(r"[\s─-╿]", "", f"{result.stdout}\n{result.stderr}")
    assert CANARY not in squeezed and CANARY[:12] not in squeezed, squeezed


@pytest.mark.parametrize("command", ["merge", "report"])
def test_two_fields_are_refused_in_the_plural_by_both_commands(shard, command):
    (shard / RESULTS).write_text(
        _record(**{FIELD: REFERENCE, OTHER_FIELD: OTHER_REFERENCE}), encoding="utf-8"
    )
    result = _run(command, shard)
    printed = _plain(result)
    assert result.exit_code == 3, printed
    assert FIELD in printed and REFERENCE in printed, printed
    assert OTHER_FIELD in printed and OTHER_REFERENCE in printed, printed
    assert PLURAL_FIELDS in printed, printed
    assert OTHERS in printed, printed
    assert SINGULAR not in printed, printed
    _assert_no_value(result)


@pytest.mark.parametrize("command", ["merge", "report"])
def test_one_field_is_refused_in_the_singular_by_both_commands(shard, command):
    """The control: one field keeps the singular wording in both commands."""
    (shard / RESULTS).write_text(_record(**{FIELD: REFERENCE}), encoding="utf-8")
    result = _run(command, shard)
    printed = _plain(result)
    assert result.exit_code == 3, printed
    assert FIELD in printed and REFERENCE in printed, printed
    assert SINGULAR in printed, printed
    assert OTHERS not in printed and PLURAL_FIELDS not in printed, printed
    _assert_no_value(result)
