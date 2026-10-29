# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A value a config file reads from the environment is recorded as its
reference at the entry it ends up in, after every ``patch`` operation.

The record of a configuration (a results file's ``ash_config``, what the
off-host reporters send, the session profile ``save(as_written=True)`` writes)
holds each value the configuration's files read from the environment as the
reference the file wrote. Were each placed by its operation's own path, and an
append by the last entry that holds the value, an operation after it that
inserts in front of it or removes an entry before it would move the value, and two
equal appends would get one index: the record would name another entry and the
value be written and sent as it was read. So each is followed through the
operations to its entry, as config_sources follows the references get_config
marks. The values are 1, 6, 9 and 25 characters long, since a check that
looked for the value's text would miss a short one.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, List, Optional

import pytest
import yaml

from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit

REFERENCE = "${ASH_PROBE_MOVED}"
POINTER = "/global_settings/ignore_paths"

VALUES = {
    1: "Q",
    6: "Qw7r9z",
    9: "Qw7r9zK2m",
    25: "Qw7r9zK2m4Lx8Pv3Hn6Tb1Yc5",
}


@pytest.fixture(autouse=True)
def _environment(monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)


def _add(index: str, path: str) -> str:
    return (
        f"  - op: add\n    path: {POINTER}/{index}\n"
        f"    value:\n      path: {path}\n      reason: r\n"
    )


def _remove(index: str) -> str:
    return f"  - op: remove\n    path: {POINTER}/{index}\n"


def _file(entries: List[str], ops: List[str], head: str = "") -> str:
    listed = "".join(f"    - path: {entry}\n      reason: r\n" for entry in entries)
    return (
        f"project_name: demo\n{head}global_settings:\n  ignore_paths:\n{listed}"
        "patch:\n" + "".join(ops)
    )


#: Each file, and the paths its record holds: REFERENCE where the value is.
SHAPES = {
    "insert-then-insert": (
        _file(["kept"], [_add("0", REFERENCE), _add("0", "lit")]),
        ["lit", REFERENCE, "kept"],
    ),
    "add-then-remove-before": (
        _file(["kept"], [_add("1", REFERENCE), _remove("0")]),
        [REFERENCE],
    ),
    "append-twice": (
        _file(["kept"], [_add("-", REFERENCE), _add("-", REFERENCE)]),
        ["kept", REFERENCE, REFERENCE],
    ),
    "own-entry-shifted": (
        _file([REFERENCE], [_add("0", "lit")]),
        ["lit", REFERENCE],
    ),
}


def _ignore_paths(data: Any) -> Optional[List[str]]:
    """The ignore paths in ``data``, wherever its configuration is held."""
    if isinstance(data, dict):
        settings = data.get("global_settings")
        if isinstance(settings, dict) and "ignore_paths" in settings:
            return [entry["path"] for entry in settings["ignore_paths"]]
        for value in data.values():
            found = _ignore_paths(value)
            if found is not None:
                return found
    return None


class _Loader(yaml.SafeLoader):
    """Reads an ``!ENV`` scalar as the reference it holds."""


_Loader.add_constructor("!ENV", lambda loader, node: loader.construct_scalar(node))


def _sinks(config_file: Path, tmp_path: Path) -> dict:
    config = resolve_config(config_file)
    results = AshAggregatedResults(ash_config=config)
    record = json.loads(results.model_dump_json(by_alias=True))
    sent = json.loads(json.dumps(results.to_simple_dict(), default=str))
    profile = tmp_path / "session" / "profile.yaml"
    profile.parent.mkdir(exist_ok=True)
    config.save(profile, as_written=True)
    written = yaml.load(profile.read_text(encoding="utf-8"), Loader=_Loader)
    return {
        "record": record["ash_config"],
        "sent": sent,
        "profile": written,
    }


@pytest.mark.parametrize("length", sorted(VALUES))
@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_the_value_is_recorded_as_its_reference_at_its_entry(
    tmp_path, monkeypatch, shape, length
):
    value = VALUES[length]
    monkeypatch.setenv("ASH_PROBE_MOVED", value)
    text, recorded = SHAPES[shape]
    config_file = tmp_path / ".ash.yaml"
    config_file.write_text(text, encoding="utf-8")
    # The control: the run reads the value at each place the record names.
    loaded = [
        entry.path for entry in resolve_config(config_file).global_settings.ignore_paths
    ]
    assert loaded == [value if entry == REFERENCE else entry for entry in recorded]

    sinks = _sinks(config_file, tmp_path)

    for name, data in sinks.items():
        assert _ignore_paths(data) == recorded, (name, data)
        if length > 1:
            assert value not in json.dumps(data), (name, data)


def test_a_base_s_value_the_extending_file_s_patch_moves_is_recorded_at_its_entry(
    tmp_path, monkeypatch
):
    value = VALUES[25]
    monkeypatch.setenv("ASH_PROBE_MOVED", value)
    (tmp_path / "base.yaml").write_text(
        f"global_settings:\n  ignore_paths:\n    - path: {REFERENCE}\n      reason: r\n",
        encoding="utf-8",
    )
    config_file = tmp_path / ".ash.yaml"
    config_file.write_text(
        "project_name: demo\nextends: base.yaml\npatch:\n" + _add("0", "lit"),
        encoding="utf-8",
    )

    sinks = _sinks(config_file, tmp_path)

    for name, data in sinks.items():
        assert _ignore_paths(data) == ["lit", REFERENCE], (name, data)
        assert value not in json.dumps(data), (name, data)
