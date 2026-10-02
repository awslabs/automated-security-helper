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

    def test_preserves_comments_on_first_suppression(self, tmp_path: Path):
        """First suppression into a commented config must not strip comments.

        This is the MED-1 regression: global_settings exists but has no
        suppressions key, which used to route to a full yaml.safe_dump rewrite
        that dropped every comment. It must now text-insert instead.
        """
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text(
            "# Top-of-file rationale, must survive\n"
            "project_name: my-project\n"
            "global_settings:\n"
            "  # keep this note about the threshold\n"
            "  severity_threshold: MEDIUM\n"
        )

        add_suppression_to_config(
            config_path,
            AshSuppression(rule_id="R-1", path="x.py", reason="ok"),
        )

        written = config_path.read_text()
        assert "# Top-of-file rationale, must survive" in written
        assert "# keep this note about the threshold" in written

        data = yaml.safe_load(written)
        assert data["project_name"] == "my-project"
        assert data["global_settings"]["severity_threshold"] == "MEDIUM"
        assert data["global_settings"]["suppressions"][0]["rule_id"] == "R-1"

    def test_preserves_comments_when_appending_to_existing_list(self, tmp_path: Path):
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text(
            "global_settings:\n"
            "  suppressions:\n"
            "    # an existing, reviewed entry\n"
            "    - rule_id: OLD-1\n"
            "      path: old.py\n"
            "      reason: legacy\n"
        )

        add_suppression_to_config(
            config_path,
            AshSuppression(rule_id="NEW-2", path="new.py", reason="accepted"),
        )

        written = config_path.read_text()
        assert "# an existing, reviewed entry" in written
        rule_ids = [
            s["rule_id"]
            for s in yaml.safe_load(written)["global_settings"]["suppressions"]
        ]
        assert rule_ids == ["OLD-1", "NEW-2"]

    def test_appends_block_when_no_global_settings(self, tmp_path: Path):
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text("# only a project name here\nproject_name: p\n")

        add_suppression_to_config(
            config_path,
            AshSuppression(rule_id="C-1", path="c.py", reason="ok"),
        )

        written = config_path.read_text()
        assert "# only a project name here" in written
        data = yaml.safe_load(written)
        assert data["project_name"] == "p"
        assert data["global_settings"]["suppressions"][0]["rule_id"] == "C-1"

    @pytest.mark.parametrize(
        "reason",
        [
            'He said "hi" to the scanner',
            "path C:\\Users\\x and a : colon",
            "trailing backslash \\",
            "hash # and braces {} and brackets []",
        ],
    )
    def test_reason_with_special_characters_round_trips(
        self, tmp_path: Path, reason: str
    ):
        """A reason with quotes/backslashes/colons must produce valid YAML.

        The old hand-rolled _yaml_scalar double-quoted without escaping embedded
        quotes or backslashes, so these reasons produced invalid YAML on the
        supposedly-safe append path. Free-text reasons from the dialog are
        exactly where this hit.
        """
        config_path = tmp_path / ".ash.yaml"
        # Start with an existing suppressions list so the append path is exercised.
        config_path.write_text(
            "global_settings:\n"
            "  suppressions:\n"
            "    - rule_id: OLD-1\n"
            "      path: old.py\n"
            "      reason: legacy\n"
        )

        add_suppression_to_config(
            config_path,
            AshSuppression(rule_id="Q-1", path="q.py", reason=reason),
        )

        # Must parse, and the reason must survive verbatim.
        data = yaml.safe_load(config_path.read_text())
        entries = {s["rule_id"]: s for s in data["global_settings"]["suppressions"]}
        assert entries["Q-1"]["reason"] == reason
