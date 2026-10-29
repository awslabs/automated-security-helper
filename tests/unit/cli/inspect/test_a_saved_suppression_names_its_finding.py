# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A suppression the findings explorer saves names the finding it was saved for.

The dialog wrote a finding with no file as the path ``*`` and a finding with no
rule id with no rule: an entry that never applied to the chosen finding and
suppressed the rule in every file, or every rule at the path. It wrote the file as
the results record it (``./src/x.py``, ``src//x.py``), while the scan matches a
suppression against the folded spelling, so the saved entry never applied. And it
wrote the file as a glob pattern, so ``[``, ``*`` and ``?`` in the name widened it
to other files.
"""

from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml

from automated_security_helper.cli.inspect.inspect_findings_app import (
    SuppressDialog,
    _suppression_path,
)
from automated_security_helper.utils.path_matching import match_glob

pytestmark = pytest.mark.unit


def _press_save(finding: dict, config_path: Path) -> tuple[MagicMock, MagicMock]:
    """Press Save on a dialog over *finding*; the error field and dismiss mocks."""
    dialog = SuppressDialog(finding, config_path)
    error_field = MagicMock()
    inputs = {
        "#reason_input": MagicMock(value="accepted after review"),
        "#expiration_input": MagicMock(value=""),
        "#suppression-error": error_field,
    }
    dialog.query_one = lambda selector, _type=None: inputs[selector]
    dialog.dismiss = MagicMock()
    dialog.on_button_pressed(MagicMock(button=MagicMock(id="btn_suppress")))
    return error_field, dialog.dismiss


def _saved_entries(config_path: Path) -> list:
    data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    return data["global_settings"]["suppressions"]


class TestAFindingWithoutAFileOrARuleIsNotSaved:
    def test_no_file_writes_nothing_and_says_why(self, tmp_path):
        config_path = tmp_path / ".ash.yaml"

        error_field, dismiss = _press_save({"rule_id": "B101", "line": 10}, config_path)

        assert dismiss.call_args is None, dismiss.call_args
        ((shown,), _) = error_field.update.call_args
        assert "reports no file" in str(shown), shown
        assert not config_path.exists()

    def test_no_rule_id_writes_nothing_and_says_why(self, tmp_path):
        config_path = tmp_path / ".ash.yaml"

        error_field, dismiss = _press_save(
            {"rule_id": None, "file": "src/app.py", "line": 10}, config_path
        )

        assert dismiss.call_args is None, dismiss.call_args
        ((shown,), _) = error_field.update.call_args
        assert "reports no rule id" in str(shown), shown
        assert not config_path.exists()


class TestTheSavedPathIsTheOneTheScanMatches:
    def test_a_dot_and_a_double_slash_are_folded(self, tmp_path):
        config_path = tmp_path / ".ash.yaml"

        _, dismiss = _press_save(
            {"rule_id": "B101", "file": "./src//app.py", "line": 10}, config_path
        )

        ((outcome,), _) = dismiss.call_args
        assert outcome == SuppressDialog.SAVED
        (entry,) = _saved_entries(config_path)
        assert entry["path"] == "src/app.py", entry
        # The spelling the scan compares against, after its own folding.
        assert match_glob("src/app.py", entry["path"])

    def test_glob_characters_in_the_name_name_that_file_only(self, tmp_path):
        config_path = tmp_path / ".ash.yaml"

        _press_save({"rule_id": "B101", "file": "src/x[1].py", "line": 10}, config_path)

        (entry,) = _saved_entries(config_path)
        assert entry["path"] == "src/x[[]1].py", entry
        assert match_glob("src/x[1].py", entry["path"])
        assert not match_glob("src/x1.py", entry["path"])

    def test_a_backslash_in_the_name_is_refused_not_widened(self, tmp_path):
        config_path = tmp_path / ".ash.yaml"

        error_field, dismiss = _press_save(
            {"rule_id": "B101", "file": "src\\x.py", "line": 10}, config_path
        )

        assert dismiss.call_args is None, dismiss.call_args
        ((shown,), _) = error_field.update.call_args
        assert "backslash" in str(shown), shown
        assert not config_path.exists()

    @pytest.mark.parametrize(
        ("recorded", "expected"),
        [
            ("src/app.py", "src/app.py"),
            ("./src/app.py", "src/app.py"),
            ("src//app.py", "src/app.py"),
            ("src/./app.py", "src/app.py"),
            ("src/../app.py", "src/../app.py"),
            ("a*b.py", "a[*]b.py"),
            ("https://host/x?y", "https://host/x[?]y"),
        ],
    )
    def test_the_path_written_for_a_recorded_uri(self, recorded, expected):
        assert _suppression_path(recorded) == expected
