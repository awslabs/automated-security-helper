# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash merge`` names every recorded reference it cannot supply, in one refusal.

A shard records a value its scan read from the environment as the reference its
config file wrote. A fixed-choice field such as ``global_settings.severity_threshold``
or ``output_formats`` cannot hold one, so the merge takes the field from
``--config-overrides`` or the ``--config`` file, or refuses
(config/recorded_config.py, take_own_values).

With several shards the refusal covers all of them: it names each field with the
shard and the results file that recorded it, as the refusal for shards that
disagree on a verdict setting does. Stopping at the first shard left the operator
to fix one field, run the merge again, and meet the next. A field that several
shards record as the same reference is one entry, with each shard and results file
listed under it.
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
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.sharding import ShardAssignment
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerStatusInfo,
)

pytestmark = pytest.mark.unit

FIELD = "global_settings.severity_threshold"
OTHER_FIELD = "output_formats"
REFERENCE = "${ASH_PROBE_SEV:LOW}"
OTHER_REFERENCE = "${ASH_PROBE_SEV_TWO:LOW}"
FORMATS_REFERENCE = "${ASH_PROBE_FORMATS}"
RESULTS = "ash_aggregated_results.json"
# The variables' value where the merge runs. It reads none of them, so it
# appears in nothing the merge prints.
CANARY = "ash-canary-7f3e-0123456789"
SCANNERS = ("bandit", "semgrep")


def _assert_no_value(text: str) -> None:
    """Whitespace and box-drawing characters removed, so a value wrapped across
    lines or a panel border still counts; and its leading part, so a truncated
    one does too."""
    squeezed = re.sub(r"[\s─-╿]", "", text)
    assert CANARY not in squeezed and CANARY[:12] not in squeezed, text


def _record(index: int, count: int, **recorded: str) -> str:
    """Shard *index* of *count*, as a scan whose config read the fields of
    *recorded* from the environment writes it.

    Each key of *recorded* is a field of the record; ``global_settings`` is
    spelled ``global_settings.severity_threshold``."""
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
    for name in (
        "ASH_PROBE_SEV",
        "ASH_PROBE_SEV_TWO",
        "ASH_PROBE_FORMATS",
    ):
        monkeypatch.setenv(name, CANARY)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    # Control: a reference does resolve to the canary in this process.
    assert resolve_env_references(REFERENCE) == CANARY
    for name in ("shard0", "shard1"):
        (tmp_path / name).mkdir()
    return tmp_path


def _write(shards: Path, index: int, count: int = 2, **recorded: str) -> Path:
    directory = shards / f"shard{index}"
    (directory / RESULTS).write_text(
        _record(index, count, **recorded), encoding="utf-8"
    )
    return directory


def _merge(directories, *extra: str):
    arguments = ["merge", "--output-dir", "merged"]
    for directory in directories:
        arguments += ["--results", str(directory)]
    return CliRunner().invoke(app, [*arguments, *extra], env={"COLUMNS": "300"})


def _printed(result) -> str:
    return " ".join(f"{result.stdout} {result.stderr}".split())


def _plain(result) -> str:
    """What the command printed with box-drawing characters turned into spaces and
    whitespace collapsed, so a phrase wrapped across lines or past a panel border
    reads as one."""
    text = re.sub(r"[─-╿]", " ", f"{result.stdout} {result.stderr}")
    return " ".join(text.split())


REFUSAL_START = "The configuration recorded in these results cannot be used as it is:"
REFUSAL_END = (
    r"or a --config file that sets it\."
    r"(?: Supply each of the other fields named the same way\.)?"
)


def _refusal(result) -> str:
    """The merge's refusal alone, from the sentence it begins with to the last
    sentence it ends with. A shard that records a reference raises a log warning
    as it loads, before any override is applied, and that warning names the field
    even when the operator supplies it; a check that the refusal does not name a
    field reads this and not everything the command printed."""
    match = re.search(f"{re.escape(REFUSAL_START)}.*?{REFUSAL_END}", _plain(result))
    assert match, _printed(result)
    return match.group(0)


def test_two_shards_each_missing_a_field_are_refused_once_naming_both(shards):
    """The refusal names the threshold shard 0 recorded and the output formats
    shard 1 recorded, each with its results file. Stopping at the first shard
    named the threshold alone, with no file."""
    first = _write(shards, 0, **{FIELD: REFERENCE})
    second = _write(shards, 1, **{OTHER_FIELD: FORMATS_REFERENCE})
    result = _merge([first, second])
    printed = _printed(result)
    assert result.exit_code == 3, printed
    assert FIELD in printed and REFERENCE in printed, printed
    assert OTHER_FIELD in printed and FORMATS_REFERENCE in printed, printed
    assert "shard 0" in printed and "shard 1" in printed, printed
    assert f"shard0/{RESULTS}" in printed, printed
    assert f"shard1/{RESULTS}" in printed, printed
    assert "--config-overrides" in printed, printed
    _assert_no_value(f"{result.stdout}\n{result.stderr}")
    assert not (Path("merged") / RESULTS).exists()


def test_a_field_recorded_by_two_shards_names_both_files(shards):
    """The same field, recorded as a different reference by each shard: both
    references and both files are named, in the one refusal."""
    first = _write(shards, 0, **{FIELD: REFERENCE})
    second = _write(shards, 1, **{FIELD: OTHER_REFERENCE})
    result = _merge([first, second])
    printed = _printed(result)
    assert result.exit_code == 3, printed
    assert REFERENCE in printed and OTHER_REFERENCE in printed, printed
    assert f"shard0/{RESULTS}" in printed, printed
    assert f"shard1/{RESULTS}" in printed, printed
    _assert_no_value(f"{result.stdout}\n{result.stderr}")
    assert not (Path("merged") / RESULTS).exists()


def test_a_reference_two_shards_recorded_is_named_once_with_both_shards(shards):
    """Two shards that record the same field as the same reference are one entry
    in the refusal, with each shard and its results file listed under it. The
    entry per shard repeated the field and the reference once for every shard,
    which grows with the shard count in the common case of one pipeline config."""
    first = _write(shards, 0, **{FIELD: REFERENCE})
    second = _write(shards, 1, **{FIELD: REFERENCE})
    result = _merge([first, second])
    printed = _plain(result)
    assert result.exit_code == 3, printed
    assert printed.count(f"{FIELD} is recorded as {REFERENCE}") == 1, printed
    assert re.search(
        rf"in shard 0 \(\S*shard0/{RESULTS}\) and shard 1 \(\S*shard1/{RESULTS}\)",
        printed,
    ), printed
    _assert_no_value(f"{result.stdout}\n{result.stderr}")
    assert not (Path("merged") / RESULTS).exists()


@pytest.mark.parametrize(
    ("places", "listed"),
    [
        (["shard 0 (a)"], "shard 0 (a)"),
        (["shard 0 (a)", "shard 1 (b)"], "shard 0 (a) and shard 1 (b)"),
        (
            ["shard 0 (a)", "shard 1 (b)", "shard 2 (c)"],
            "shard 0 (a), shard 1 (b), and shard 2 (c)",
        ),
    ],
    ids=["one", "two", "three"],
)
def test_the_places_a_reference_was_recorded_read_as_a_list(places, listed):
    """One place stands alone, two are joined by "and", and three or more are a
    comma list ending in ", and" (the Oxford comma)."""
    from automated_security_helper.cli.merge import _listed

    assert _listed(places) == listed


def test_a_field_the_operator_supplies_is_not_named(shards):
    """An override that names the threshold supplies it for every shard, so the
    refusal is for the output formats alone, and names the file that recorded
    them, not the one that recorded the threshold. The check reads the refusal
    alone: shard 0's log warning, raised as the shard loads, still names the
    threshold it recorded, which is documented and not the refusal's."""
    first = _write(shards, 0, **{FIELD: REFERENCE})
    second = _write(shards, 1, **{OTHER_FIELD: FORMATS_REFERENCE})
    result = _merge([first, second], "--config-overrides", f"{FIELD}=HIGH")
    printed = _printed(result)
    refusal = _refusal(result)
    assert result.exit_code == 3, printed
    assert OTHER_FIELD in refusal and FORMATS_REFERENCE in refusal, refusal
    assert f"shard1/{RESULTS}" in refusal, refusal
    assert f"shard0/{RESULTS}" not in refusal, refusal
    assert FIELD not in refusal and REFERENCE not in refusal, refusal
    _assert_no_value(f"{result.stdout}\n{result.stderr}")
    assert not (Path("merged") / RESULTS).exists()


def test_one_shard_is_refused_naming_its_field_reference_shard_and_file(shards):
    """The control: with one shard recorded as a reference, the refusal names the
    field and the reference, the shard and its results file, and the way to supply
    the field, and no merged file is written."""
    only = _write(shards, 0, count=1, **{FIELD: REFERENCE})
    result = _merge([only])
    printed = _printed(result)
    assert result.exit_code == 3, printed
    assert FIELD in printed and REFERENCE in printed, printed
    assert "in shard 0 (" in printed and f"shard0/{RESULTS}" in printed, printed
    assert f"--config-overrides '{FIELD}=<value>'" in printed, printed
    assert "--config" in printed, printed
    _assert_no_value(f"{result.stdout}\n{result.stderr}")
    assert not (Path("merged") / RESULTS).exists()
