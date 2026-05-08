# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for add_suppression_to_config."""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

import yaml
import pytest

from automated_security_helper.config.ash_config import add_suppression_to_config
from automated_security_helper.models.core import AshSuppression


def _future_date() -> str:
    return (date.today() + timedelta(days=30)).strftime("%Y-%m-%d")


class TestAddSuppressionToConfig:
    """Tests for the add_suppression_to_config helper."""

    def test_creates_file_when_missing(self, tmp_path: Path):
        config_path = tmp_path / ".ash.yaml"
        suppression = AshSuppression(
            rule_id="TEST-001",
            path="src/app.py",
            reason="false positive",
        )

        add_suppression_to_config(config_path, suppression)

        assert config_path.exists()
        data = yaml.safe_load(config_path.read_text())
        suppressions = data["global_settings"]["suppressions"]
        assert len(suppressions) == 1
        assert suppressions[0]["rule_id"] == "TEST-001"
        assert suppressions[0]["path"] == "src/app.py"
        assert suppressions[0]["reason"] == "false positive"

    def test_appends_to_existing_suppressions(self, tmp_path: Path):
        config_path = tmp_path / ".ash.yaml"
        initial = {
            "global_settings": {
                "suppressions": [
                    {"rule_id": "OLD-001", "path": "old.py", "reason": "legacy"}
                ]
            }
        }
        config_path.write_text(yaml.safe_dump(initial))

        suppression = AshSuppression(
            rule_id="NEW-002",
            path="new.py",
            reason="accepted risk",
        )
        add_suppression_to_config(config_path, suppression)

        data = yaml.safe_load(config_path.read_text())
        suppressions = data["global_settings"]["suppressions"]
        assert len(suppressions) == 2
        assert suppressions[0]["rule_id"] == "OLD-001"
        assert suppressions[1]["rule_id"] == "NEW-002"

    def test_preserves_unrelated_config_keys(self, tmp_path: Path):
        config_path = tmp_path / ".ash.yaml"
        initial = {
            "project_name": "my-project",
            "global_settings": {"severity_threshold": "HIGH"},
        }
        config_path.write_text(yaml.safe_dump(initial))

        suppression = AshSuppression(
            rule_id="R-1",
            path="x.py",
            reason="ok",
        )
        add_suppression_to_config(config_path, suppression)

        data = yaml.safe_load(config_path.read_text())
        assert data["project_name"] == "my-project"
        assert data["global_settings"]["severity_threshold"] == "HIGH"
        assert len(data["global_settings"]["suppressions"]) == 1

    def test_includes_optional_fields(self, tmp_path: Path):
        config_path = tmp_path / ".ash.yaml"
        exp = _future_date()
        suppression = AshSuppression(
            rule_id="R-2",
            path="foo.py",
            reason="temporary",
            expiration=exp,
            line_start=10,
            line_end=20,
        )

        add_suppression_to_config(config_path, suppression)

        data = yaml.safe_load(config_path.read_text())
        entry = data["global_settings"]["suppressions"][0]
        assert entry["expiration"] == exp
        assert entry["line_start"] == 10
        assert entry["line_end"] == 20

    def test_excludes_none_fields(self, tmp_path: Path):
        config_path = tmp_path / ".ash.yaml"
        suppression = AshSuppression(
            path="bar.py",
            reason="no rule id needed",
        )

        add_suppression_to_config(config_path, suppression)

        data = yaml.safe_load(config_path.read_text())
        entry = data["global_settings"]["suppressions"][0]
        assert "rule_id" not in entry
        assert "line_start" not in entry
        assert "line_end" not in entry
        assert "expiration" not in entry

    def test_handles_empty_existing_file(self, tmp_path: Path):
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text("")

        suppression = AshSuppression(
            rule_id="E-1",
            path="e.py",
            reason="empty file test",
        )

        add_suppression_to_config(config_path, suppression)

        data = yaml.safe_load(config_path.read_text())
        assert len(data["global_settings"]["suppressions"]) == 1

    def test_creates_parent_directories(self, tmp_path: Path):
        config_path = tmp_path / "nested" / "dir" / ".ash.yaml"
        suppression = AshSuppression(
            rule_id="N-1",
            path="n.py",
            reason="nested dirs",
        )

        add_suppression_to_config(config_path, suppression)

        assert config_path.exists()
        data = yaml.safe_load(config_path.read_text())
        assert len(data["global_settings"]["suppressions"]) == 1
