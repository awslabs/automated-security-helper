# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A configuration that names a file whose name is not UTF-8 runs, and reads back as written.

An ignore path or a suppression can name such a file: given as an argument, the byte
reaches argv and Python reads it as a lone surrogate; in a YAML double-quoted string or
a JSON string, the escape ``\\udce9`` reads as the same surrogate. The scanned
repository's own ``.ash`` config is read that way too, so a pull request can add one.

- Each such configuration gives a scan that writes its results file and keeps the
  findings of the files it does not name.
- A ``project_name`` holding one is refused at exit 3, before the scan, and the
  refusal does not quote the value.
- The configuration a results file records reads back with the name the run was given,
  the surrogate itself, so a run over those results (``ash report``,
  ``--use-existing``, ``ash merge``) ignores the file the run ignored.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, List

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils.suppression_matcher import ignore_path_matches
from tests.utils import undecodable_names as names
from tests.utils.undecodable_names import (
    ABSENT,
    CONTROL,
    KEEP,
    ODD,
    ODD_BYTES,
    RECORDED,
    REPORTED,
)

# Every test here plants a file whose name is not UTF-8.
if os.name == "nt":
    pytest.skip(
        "a file name that is not UTF-8 cannot exist on NTFS (names are UTF-16)",
        allow_module_level=True,
    )

#: An ignore path naming the file that is not UTF-8, in the YAML and JSON that read
#: its escape as the surrogate, and a suppression whose reason holds one.
_REPO_CONFIGS: Dict[str, bytes] = {
    ".ash/.ash.yaml": (
        "global_settings:\n"
        "  ignore_paths:\n"
        '    - path: "secr\\udce9t.py"\n'
        "      reason: not scanned\n"
        "  suppressions:\n"
        "    - path: other.py\n"
        "      rule_id: 'SECRET-*'\n"
        '      reason: "caf\\udce9"\n'
    ).encode("utf-8"),
    ".ash/.ash.json": (
        '{"global_settings": {'
        '"ignore_paths": [{"path": "secr\\udce9t.py", "reason": "not scanned"}], '
        '"suppressions": [{"path": "other.py", "rule_id": "SECRET-*", '
        '"reason": "caf\\udce9"}]}}'
    ).encode("utf-8"),
}

#: A project name holding a surrogate, in each config file form. Its letters appear
#: nowhere else in a scan's output, so a refusal that quotes it shows.
_PROJECT_NAMES: Dict[str, bytes] = {
    ".ash/.ash.yaml": 'project_name: "zq\\udce9xv"\n'.encode("utf-8"),
    ".ash/.ash.json": '{"project_name": "zq\\udce9xv"}'.encode("utf-8"),
}


def _plain_tree(tmp_path: Path, extra: Dict[object, bytes] | None = None) -> Path:
    files: Dict[object, bytes] = {
        ODD_BYTES: names.secret_source(),
        CONTROL: names.secret_source(),
        KEEP: names.secret_source(),
    }
    files.update(extra or {})
    return names.make_tree(tmp_path / "src", files)


def _loaded(output: Path) -> AshAggregatedResults:
    """The results file, read back as every reader of it reads it."""
    return AshAggregatedResults.model_validate_json(
        names.results_file(output).read_bytes()
    )


def test_an_ignore_path_given_as_an_argument_with_the_byte_writes_the_results(
    tmp_path,
):
    source = _plain_tree(tmp_path)
    output = tmp_path / "out"
    value = (
        b'global_settings.ignore_paths+=[{"path": "'
        + ODD_BYTES
        + b'", "reason": "not scanned"}]'
    )

    ran = names.scan(tmp_path, source, output, "--config-overrides", value)

    assert ran.code == 2, ran
    _loaded(output)
    found = names.findings(output)
    assert names.decision(found, KEEP) == REPORTED, (found, ran)
    assert names.decision(found, CONTROL) == REPORTED, (found, ran)


@pytest.mark.parametrize("config_name", sorted(_REPO_CONFIGS))
def test_a_repositorys_own_config_naming_the_file_writes_the_results(
    tmp_path, config_name
):
    source = _plain_tree(tmp_path, {config_name: _REPO_CONFIGS[config_name]})
    output = tmp_path / "out"

    ran = names.scan(tmp_path, source, output)

    assert ran.code == 2, ran
    _loaded(output)
    found = names.findings(output)
    assert names.decision(found, KEEP) == REPORTED, (found, ran)
    assert names.decision(found, CONTROL) == REPORTED, (found, ran)


@pytest.mark.parametrize("config_name", sorted(_PROJECT_NAMES))
def test_a_project_name_holding_one_is_refused_without_its_value(tmp_path, config_name):
    source = _plain_tree(tmp_path, {config_name: _PROJECT_NAMES[config_name]})
    output = tmp_path / "out"

    ran = names.scan(tmp_path, source, output)

    assert ran.code == 3, ran
    assert not names.results_file(output).exists()
    said = ran.stdout + ran.stderr
    assert "'project_name'" in said, said
    assert "zq" not in said and "xv" not in said, said
    assert "Traceback" not in said, said


def _operator_config(tmp_path: Path) -> Path:
    config = tmp_path / "operator.yaml"
    config.write_text(
        "global_settings:\n"
        "  ignore_paths:\n"
        '    - path: "secr\\udce9t.py"\n'
        "      reason: not scanned\n"
        f"    - path: '{CONTROL}'\n"
        "      reason: not scanned\n",
        encoding="utf-8",
    )
    return config


def _recorded_ignore_paths(model: AshAggregatedResults) -> List[str]:
    assert model.ash_config is not None
    return sorted(entry.path for entry in model.ash_config.global_settings.ignore_paths)


def test_the_recorded_config_reads_back_the_name_the_run_was_given(tmp_path):
    source = _plain_tree(tmp_path)
    output = tmp_path / "out"

    ran = names.scan(
        tmp_path, source, output, "--config", str(_operator_config(tmp_path))
    )

    assert names.results_file(output).is_file(), ran
    recorded = _recorded_ignore_paths(_loaded(output))
    # ascii(): a report holding a lone surrogate cannot be sent between workers.
    assert recorded == sorted([ODD, CONTROL]), ascii(recorded)
    for path in recorded:
        assert ignore_path_matches(ODD, path) is (path == ODD), ascii(path)


def test_a_report_over_existing_results_reads_back_the_name(tmp_path):
    source = _plain_tree(tmp_path)
    output = tmp_path / "out"
    config = _operator_config(tmp_path)
    first = names.scan(tmp_path, source, output, "--config", str(config))
    assert names.results_file(output).is_file(), first

    again = names.scan(
        tmp_path, source, output, "--config", str(config), "--use-existing"
    )

    assert again.code == first.code, (first, again)
    recorded = _recorded_ignore_paths(_loaded(output))
    assert recorded == sorted([ODD, CONTROL]), ascii(recorded)
    found = names.findings(output)
    assert names.decision(found, RECORDED) == ABSENT, (found, again)
    assert names.decision(found, KEEP) == REPORTED, (found, again)

    report = names.ash(
        tmp_path, ["report", "--output-dir", str(output), "--format", "flat-json"]
    )
    assert report.code == 0, report
    assert _recorded_ignore_paths(_loaded(output)) == sorted([ODD, CONTROL])


def test_a_merge_applies_the_recorded_config_to_the_name(tmp_path):
    """Shards scanned with --ignore-suppressions keep every finding; the merge applies
    the configuration they recorded, as a scan without that flag would have."""
    source = _plain_tree(tmp_path)
    config = _operator_config(tmp_path)
    shards = []
    for index in (0, 1):
        output = tmp_path / f"shard-{index}"
        ran = names.scan(
            tmp_path,
            source,
            output,
            "--config",
            str(config),
            "--ignore-suppressions",
            "--shard-index",
            str(index),
            "--shard-count",
            "2",
        )
        assert names.results_file(output).is_file(), ran
        shards.append(output)
    merged = tmp_path / "merged"

    ran = names.ash(
        tmp_path,
        [
            "merge",
            *[part for shard in shards for part in ("--results", str(shard))],
            "--output-dir",
            str(merged),
        ],
    )

    assert names.results_file(merged).is_file(), ran
    found = names.findings(merged)
    assert names.decision(found, CONTROL) == ABSENT, (found, ran)
    assert names.decision(found, KEEP) == REPORTED, (found, ran)
    assert names.decision(found, RECORDED) == ABSENT, (found, ran)
    recorded = _recorded_ignore_paths(_loaded(merged))
    assert recorded == sorted([ODD, CONTROL]), ascii(recorded)


def test_the_odd_name_and_its_spelled_twin_read_back_as_one_name_through_a_merge(
    tmp_path,
):
    """The raw name and a name spelled with the escape's six characters have one record
    form (a known limit on POSIX, where a file may be named with those characters), so
    the merged results record one text for both entries, each reads back as the raw
    name, and each ignores the file."""
    source = _plain_tree(tmp_path)
    config = tmp_path / "operator.yaml"
    config.write_text(
        "global_settings:\n"
        "  ignore_paths:\n"
        '    - path: "secr\\udce9t.py"\n'
        "      reason: the file named with the byte\n"
        "    - path: 'secr\\udce9t.py'\n"
        "      reason: the file named with the six characters\n",
        encoding="utf-8",
    )
    shards = []
    for index in (0, 1):
        output = tmp_path / f"shard-{index}"
        ran = names.scan(
            tmp_path,
            source,
            output,
            "--config",
            str(config),
            "--shard-index",
            str(index),
            "--shard-count",
            "2",
        )
        assert names.results_file(output).is_file(), ran
        shards.append(output)
    merged = tmp_path / "merged"

    ran = names.ash(
        tmp_path,
        [
            "merge",
            *[part for shard in shards for part in ("--results", str(shard))],
            "--output-dir",
            str(merged),
        ],
    )

    assert names.results_file(merged).is_file(), ran
    stored = json.loads(names.results_file(merged).read_bytes().decode("utf-8"))
    texts = [
        entry["path"]
        for entry in stored["ash_config"]["global_settings"]["ignore_paths"]
    ]
    assert texts == [RECORDED, RECORDED], texts
    recorded = _recorded_ignore_paths(_loaded(merged))
    assert recorded == [ODD, ODD], ascii(recorded)
    found = names.findings(merged)
    assert names.decision(found, RECORDED) == ABSENT, (found, ran)
    assert names.decision(found, CONTROL) == REPORTED, (found, ran)
