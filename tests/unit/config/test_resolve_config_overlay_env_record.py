# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The workspace overlay's environment reads are recorded like the chain's own.

``resolve_config(overlay_config_path=...)`` merges the operator's config over a
project's own before the model is built, and takes it alone where the project
has no config file, so a value the overlay read with ``!ENV`` is in the
configuration. The results file's ``ash_config`` record (record_of_config), the
payload an off-host reporter sends and the free-text redaction read
``_written_references`` and ``_environment_values``; a load that put the
overlay's reads only in ``_environment_references`` left the record and the
redaction with the resolved values.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from automated_security_helper.config.config_validator import (
    REDACTED,
    record_of_config,
    redact_values,
)
from automated_security_helper.config.resolve_config import resolve_config

pytestmark = pytest.mark.unit

VARIABLE = "ASH_OVERLAY_RECORD_CANARY"
#: Long enough to be redacted wherever it appears, and unlike any other text.
VALUE = "qzoverlay-reason-7731"
PLACE = ("global_settings", "ignore_paths", 0, "reason")


@pytest.fixture(autouse=True)
def _environment(monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)
    monkeypatch.setenv(VARIABLE, VALUE)


def _project(tmp_path: Path, document) -> Path:
    path = tmp_path / "repo" / ".ash" / ".ash.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return path


def _operator(tmp_path: Path) -> Path:
    """The operator's file, outside the scanned tree, reading one ignore
    path's reason from the environment."""
    path = tmp_path / "operator" / "ash.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "global_settings:\n"
        "  ignore_paths:\n"
        "    - path: vendor/**\n"
        f"      reason: !ENV ${{{VARIABLE}}}\n",
        encoding="utf-8",
    )
    return path


def _resolve(tmp_path: Path, project, operator: Path):
    return resolve_config(
        config_path=project,
        source_dir=tmp_path / "repo",
        trusted_config_path=operator,
        overlay_config_path=operator,
    )


def _reason_rewrites(config):
    return [
        rewrite
        for rewrite in config._written_references
        if tuple(rewrite.path) == PLACE
    ]


def test_the_overlays_read_joins_the_values_and_the_rewrites(tmp_path):
    project = _project(tmp_path, {"project_name": "api"})

    config = _resolve(tmp_path, project, _operator(tmp_path))

    assert config.global_settings.ignore_paths[0].reason == VALUE
    assert VALUE in config._environment_values
    (rewrite,) = _reason_rewrites(config)
    assert rewrite.kind == "value"
    assert rewrite.resolved == VALUE
    assert f"${{{VARIABLE}}}" in rewrite.written


def test_the_record_keeps_the_overlays_reference_not_its_value(tmp_path):
    project = _project(tmp_path, {"project_name": "api"})
    config = _resolve(tmp_path, project, _operator(tmp_path))

    record = record_of_config(config, config.model_dump(mode="json"))

    reason = record["global_settings"]["ignore_paths"][0]["reason"]
    assert f"${{{VARIABLE}}}" in reason, reason
    assert VALUE not in json.dumps(record, default=str)


def test_free_text_redaction_hides_the_overlays_value(tmp_path):
    project = _project(tmp_path, {"project_name": "api"})
    config = _resolve(tmp_path, project, _operator(tmp_path))

    shown = redact_values(f"the reason {VALUE} was refused", config._environment_values)

    assert VALUE not in shown
    assert REDACTED in shown


def test_the_overlays_references_still_join_the_configs(tmp_path):
    """What the load recorded before: the references the views read."""
    project = _project(tmp_path, {"project_name": "api"})

    config = _resolve(tmp_path, project, _operator(tmp_path))

    places = [tuple(reference.path) for reference in config._environment_references]
    assert PLACE in places, places


def test_a_project_with_no_config_takes_the_overlay_alone_with_its_reads(
    tmp_path,
):
    """The overlay stands in for the default config where discovery finds no
    file; its reads are recorded the same way."""
    (tmp_path / "repo").mkdir()
    operator = _operator(tmp_path)

    config = resolve_config(
        source_dir=tmp_path / "repo",
        trusted_config_path=operator,
        overlay_config_path=operator,
    )

    assert config.global_settings.ignore_paths[0].reason == VALUE
    assert VALUE in config._environment_values
    assert len(_reason_rewrites(config)) == 1
    record = record_of_config(config, config.model_dump(mode="json"))
    assert VALUE not in json.dumps(record, default=str)
