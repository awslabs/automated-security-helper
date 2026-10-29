# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for add_suppression_to_config."""

from __future__ import annotations

import os
import stat
from datetime import date, timedelta
from pathlib import Path

import yaml
import pytest

from automated_security_helper.config.ash_config import add_suppression_to_config
from automated_security_helper.config.resolve_config import load_config_file
from automated_security_helper.models.core import AshSuppression
from tests.snapshot.support.cli import CONFIG_HOSTS, run_cli, simulated_host

pytestmark = pytest.mark.unit


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

    def test_a_first_suppression_into_an_empty_flow_list_parses(self, tmp_path: Path):
        """``ash config init`` writes ``suppressions: []``, so the first entry
        a user saves goes into that shape: the saved file parses and holds the
        entry."""
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text(
            "project_name: t\nglobal_settings:\n  suppressions: []\n",
            encoding="utf-8",
        )

        wrote = add_suppression_to_config(
            config_path,
            AshSuppression(rule_id="R1", path="a.py", reason="pinned"),
        )

        data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        assert wrote is True
        entries = data["global_settings"]["suppressions"]
        assert [e["rule_id"] for e in entries] == ["R1"], entries

    @pytest.mark.parametrize("eol", ["\n", "\r\n"], ids=["lf", "crlf"])
    @pytest.mark.parametrize(
        "written,why",
        [
            ("- ]broken\n", "the write does not parse"),
            ("- rule_id: OTHER\n", "the write does not hold the entry"),
        ],
    )
    def test_a_write_the_file_does_not_take_is_undone(
        self, tmp_path: Path, monkeypatch, written: str, why: str, eol: str
    ):
        """A save whose result does not parse, or does not hold the new entry,
        raises and leaves the file's bytes as they were, line endings
        included. Compared as bytes: a text read folds CRLF into LF and could
        not see a file that came back with its endings changed."""
        from automated_security_helper.config import ash_config as module

        before = (
            "project_name: t\n"
            "global_settings:\n"
            "  suppressions:\n"
            "    - rule_id: R0\n"
            "      path: b.py\n"
            "      reason: old\n"
        ).replace("\n", eol)
        config_path = tmp_path / ".ash.yaml"
        config_path.write_bytes(before.encode("utf-8"))
        monkeypatch.setattr(
            module,
            "_serialize_entry_lines",
            lambda entry, indent: [f"{indent}{written}"],
        )

        with pytest.raises(ValueError, match="is unchanged"):
            module.add_suppression_to_config(
                config_path,
                AshSuppression(rule_id="R1", path="a.py", reason="pinned"),
            )

        assert config_path.read_bytes() == before.encode("utf-8"), why

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


FIRST = {
    "rule_id": "B101",
    "path": "src/app.py",
    "reason": "asserts in tests",
    "line_start": 10,
    "line_end": 10,
    "expiration": "2099-01-31",
}


def _entries(config_path: Path) -> list:
    if config_path.name.endswith(".json"):
        import json

        data = json.loads(config_path.read_text(encoding="utf-8"))
    else:
        data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    return data["global_settings"]["suppressions"]


@pytest.mark.parametrize("name", [".ashrc.yaml", "ash.json"])
class TestSecondSuppressionForOneRuleAndPath:
    """A second suppression for a rule and path already suppressed.

    It is saved: a second line range of the same file, or a renewed expiration,
    is kept. Only an identical entry is skipped, and the return value says which
    happened, so the caller reports a save only when one was made.
    """

    @pytest.mark.parametrize(
        "change",
        [
            pytest.param({"line_start": 20, "line_end": 25}, id="line-range"),
            pytest.param({"reason": "another reason"}, id="reason"),
            pytest.param({"expiration": "2099-06-30"}, id="expiration"),
        ],
    )
    def test_a_different_one_is_saved(self, tmp_path: Path, name: str, change):
        config_path = tmp_path / name
        assert add_suppression_to_config(config_path, AshSuppression(**FIRST))

        saved = add_suppression_to_config(
            config_path, AshSuppression(**{**FIRST, **change})
        )

        assert saved is True
        entries = _entries(config_path)
        assert len(entries) == 2, entries
        assert {k: entries[1][k] for k in change} == change

    def test_an_identical_one_is_not_written_and_says_so(
        self, tmp_path: Path, name: str
    ):
        config_path = tmp_path / name
        assert add_suppression_to_config(config_path, AshSuppression(**FIRST))
        before = config_path.read_bytes()

        saved = add_suppression_to_config(config_path, AshSuppression(**FIRST))

        assert saved is False
        assert config_path.read_bytes() == before


def test_an_unquoted_expiration_in_the_file_is_the_same_date(tmp_path: Path):
    """YAML reads an unquoted 2099-01-31 as a date; it still equals the string."""
    config_path = tmp_path / ".ashrc.yaml"
    config_path.write_text(
        "global_settings:\n  suppressions:\n"
        "    - rule_id: B101\n      path: src/app.py\n      reason: asserts in tests\n"
        "      line_start: 10\n      line_end: 10\n      expiration: 2099-01-31\n",
        encoding="utf-8",
    )

    assert add_suppression_to_config(config_path, AshSuppression(**FIRST)) is False


NEW = {"rule_id": "NEW-1", "path": "a.py", "reason": "pinned"}
OLD_BLOCK = "    - rule_id: OLD\n      path: old.py\n      reason: kept\n"


def _global_settings(config_path: Path) -> dict:
    """The saved file's global_settings, read as the writer reads it: as
    bytes, decoded, with !ENV kept as text."""
    from automated_security_helper.config.ash_config import _KeepsEnvReferences

    data = yaml.load(  # nosec B506 - a SafeLoader
        config_path.read_bytes().decode("utf-8"), Loader=_KeepsEnvReferences
    )
    return data["global_settings"]


def _rules(config_path: Path) -> list:
    return [e["rule_id"] for e in _global_settings(config_path)["suppressions"]]


class TestTheListEndsAtItsSiblingKey:
    """The suppressions list ends at the first line, past blank and comment
    lines, that is indented at or below its key and is not one of its items:
    a sibling global_settings key ends it, wherever the list sits in the
    block."""

    @pytest.mark.parametrize("host", CONFIG_HOSTS, ids=lambda host: host.id)
    def test_the_config_init_writes_takes_its_first_suppression(
        self, tmp_path: Path, monkeypatch, host
    ):
        """The exact bytes ``ash config init`` writes, generated here rather
        than read from a stored copy that a rename or a mask could change:
        ``suppressions: []`` sits between ``ignore_paths`` and ``mcp``. The
        save parses, holds the entry, and changes no other line but that one.
        Both sides of the diff are read as bytes: a text read folds CRLF into
        LF and could not see a save that rewrote every line ending."""
        import difflib

        project = tmp_path / "demo-project"
        project.mkdir()
        monkeypatch.chdir(project)
        with simulated_host(monkeypatch, host):
            run = run_cli(["config", "init"])
        assert run.exit_code == 0, run.document
        config_path = project / ".ashrc.yaml"
        before = config_path.read_bytes()
        before_settings = _global_settings(config_path)

        assert add_suppression_to_config(config_path, AshSuppression(**NEW)) is True

        after_settings = _global_settings(config_path)
        assert after_settings["suppressions"] == [NEW]
        assert {k: v for k, v in after_settings.items() if k != "suppressions"} == {
            k: v for k, v in before_settings.items() if k != "suppressions"
        }
        removed = [
            line
            for line in difflib.ndiff(
                before.decode("utf-8").splitlines(keepends=True),
                config_path.read_bytes().decode("utf-8").splitlines(keepends=True),
            )
            if line.startswith("- ")
        ]
        assert removed == ["-   suppressions: []\n"], removed

    @pytest.mark.parametrize(
        "suppressions",
        [
            "  suppressions:\n" + OLD_BLOCK,
            # A block sequence may sit at its key's own indent.
            "  suppressions:\n  - rule_id: OLD\n    path: old.py\n    reason: kept\n",
        ],
        ids=["indented-items", "items-at-the-key-indent"],
    )
    def test_a_block_list_followed_by_a_sibling_key_takes_the_entry(
        self, tmp_path: Path, suppressions: str
    ):
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text(
            "global_settings:\n"
            + suppressions
            + "  # the threshold\n"
            + "  severity_threshold: MEDIUM\n",
            encoding="utf-8",
        )

        assert add_suppression_to_config(config_path, AshSuppression(**NEW)) is True

        assert _rules(config_path) == ["OLD", "NEW-1"]
        assert _global_settings(config_path)["severity_threshold"] == "MEDIUM"
        text = config_path.read_text(encoding="utf-8")
        # The comment stays on the line before its key, and the new entry goes
        # in before it: an insert between the two would orphan the comment.
        assert "  # the threshold\n  severity_threshold: MEDIUM\n" in text
        assert text.index("rule_id: NEW-1") < text.index("# the threshold")

    def test_an_empty_flow_list_followed_by_a_sibling_key_takes_the_entry(
        self, tmp_path: Path
    ):
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text(
            "global_settings:\n  suppressions: []\n  severity_threshold: MEDIUM\n",
            encoding="utf-8",
        )

        assert add_suppression_to_config(config_path, AshSuppression(**NEW)) is True

        assert _rules(config_path) == ["NEW-1"]
        assert _global_settings(config_path)["severity_threshold"] == "MEDIUM"

    @pytest.mark.parametrize("sibling", ["", "  severity_threshold: MEDIUM\n"])
    def test_a_list_written_on_its_key_line_is_refused_and_left_alone(
        self, tmp_path: Path, sibling: str
    ):
        """A non-empty flow list cannot take a block item after it. The
        refusal says so and names what to do; the file keeps its bytes."""
        config_path = tmp_path / ".ash.yaml"
        before = (
            "global_settings:\n"
            "  suppressions: [{rule_id: OLD, path: old.py, reason: kept}]\n" + sibling
        ).encode("utf-8")
        config_path.write_bytes(before)

        with pytest.raises(ValueError, match="written on its key's line") as refused:
            add_suppression_to_config(config_path, AshSuppression(**NEW))

        assert "block list" in str(refused.value)
        assert config_path.read_bytes() == before

    @pytest.mark.parametrize(
        "value_line",
        [
            "    [{rule_id: OLD, path: old.py, reason: kept}]\n",
            "    []\n",
        ],
        ids=["a-flow-list", "an-empty-flow-list"],
    )
    def test_a_flow_list_on_the_line_under_its_key_is_refused_and_left_alone(
        self, tmp_path: Path, value_line: str
    ):
        """YAML lets a mapping value start on the line under its key. A flow
        list there cannot take a block item either, so it gets the same
        refusal class as one on the key's line - the save's own words naming
        what to do - not the generic one about a config that does not parse."""
        config_path = tmp_path / ".ash.yaml"
        before = ("global_settings:\n  suppressions:\n" + value_line).encode("utf-8")
        config_path.write_bytes(before)

        with pytest.raises(ValueError, match="on the line under its key") as refused:
            add_suppression_to_config(config_path, AshSuppression(**NEW))

        assert "block list" in str(refused.value)
        assert config_path.read_bytes() == before

    @pytest.mark.parametrize(
        "before",
        [
            "global_settings:\n  suppressions:\n" + OLD_BLOCK.rstrip("\n"),
            "global_settings:\n  severity_threshold: MEDIUM",
        ],
        ids=["into-a-list", "a-new-list"],
    )
    def test_a_last_line_without_its_newline_takes_the_entry_after_it(
        self, tmp_path: Path, before: str
    ):
        """An insert after the file's last line ends that line first: the
        entry would otherwise be joined onto it."""
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text(before, encoding="utf-8")

        assert add_suppression_to_config(config_path, AshSuppression(**NEW)) is True

        assert "NEW-1" in _rules(config_path)

    def test_a_suppressions_key_nested_under_another_key_is_not_the_list(
        self, tmp_path: Path
    ):
        """Only global_settings' own child is its suppressions list: a key of
        that name one level down, under another global_settings key, is
        another value."""
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text(
            "global_settings:\n"
            "  notes:\n"
            "    suppressions:\n"
            "      - kept as notes\n"
            "  suppressions:\n" + OLD_BLOCK + "  severity_threshold: MEDIUM\n",
            encoding="utf-8",
        )

        assert add_suppression_to_config(config_path, AshSuppression(**NEW)) is True

        assert _rules(config_path) == ["OLD", "NEW-1"]
        assert _global_settings(config_path)["notes"] == {
            "suppressions": ["kept as notes"]
        }


class TestTheSaveWritesItsBytesOnce:
    """The save builds the new bytes in the file's own line endings, parses
    them in memory, and only then publishes them in one step, so no failure
    leaves the file holding part of them."""

    @pytest.mark.parametrize(
        "name,before",
        [
            (
                ".ash.yaml",
                "global_settings:\n  suppressions:\n"
                + OLD_BLOCK
                + "  severity_threshold: MEDIUM\n",
            ),
            (".ash.yaml", "global_settings:\n  severity_threshold: MEDIUM\n"),
            (".ash.yaml", "project_name: t\n"),
            (".ash.yaml", "global_settings: {severity_threshold: MEDIUM}\n"),
            (".ash.json", '{\n  "global_settings": {}\n}\n'),
        ],
        ids=["into-a-list", "a-new-list", "a-new-block", "a-rewrite", "json"],
    )
    def test_a_crlf_config_keeps_its_line_endings(
        self, tmp_path: Path, name: str, before: str
    ):
        config_path = tmp_path / name
        config_path.write_bytes(before.replace("\n", "\r\n").encode("utf-8"))

        assert add_suppression_to_config(config_path, AshSuppression(**NEW)) is True

        after = config_path.read_bytes()
        # Every line break is exactly one CRLF: a bare LF, a bare CR, and a
        # doubled CR (CRLF re-written in text mode) all unbalance the counts,
        # and PyYAML reads a lone CR as a line break, so the parse alone
        # cannot see such a corruption.
        assert after.count(b"\r") == after.count(b"\n") == after.count(b"\r\n"), after
        assert "NEW-1" in _rules(config_path)

    def test_a_save_that_would_drop_a_held_suppression_is_refused(
        self, tmp_path: Path, monkeypatch
    ):
        """Every suppression the file held is still there in the bytes about
        to be written. A list the append scan misses would otherwise get a
        second ``suppressions:`` key from the no-list case, and YAML keeps the
        last of two equal keys: the new entry would load, and the old ones
        would be gone."""
        from automated_security_helper.config import ash_config as module

        config_path = tmp_path / ".ash.yaml"
        before = ("global_settings:\n  suppressions:\n" + OLD_BLOCK).encode("utf-8")
        config_path.write_bytes(before)
        monkeypatch.setattr(
            module, "_find_suppressions_append_point", lambda lines: (None, None)
        )

        with pytest.raises(ValueError, match="is unchanged"):
            module.add_suppression_to_config(config_path, AshSuppression(**NEW))

        assert config_path.read_bytes() == before

    def test_a_refused_save_never_writes_the_file(self, tmp_path: Path, monkeypatch):
        """A result that would not parse is refused before any write: nothing
        under the config's directory is opened for writing by any route (the
        open builtin, io.open, os.open), so there is no written-then-restored
        window and no staged copy either."""
        import builtins
        import io

        from automated_security_helper.config import ash_config as module

        config_path = tmp_path / ".ash.yaml"
        before = ("global_settings:\n  suppressions:\n" + OLD_BLOCK).encode("utf-8")
        config_path.write_bytes(before)
        monkeypatch.setattr(
            module,
            "_serialize_entry_lines",
            lambda entry, indent: [f"{indent}- ]broken\n"],
        )

        def _inside_the_config_dir(file: object) -> bool:
            try:
                resolved = Path(os.fsdecode(file)).resolve()
            except (TypeError, ValueError):
                return False
            return resolved == config_path.resolve() or resolved.is_relative_to(
                tmp_path.resolve()
            )

        real_open = builtins.open
        real_os_open = os.open

        def guarded_open(file, mode="r", *args, **kwargs):
            writes = any(letter in str(mode) for letter in "wax+")
            if writes and not isinstance(file, int) and _inside_the_config_dir(file):
                raise AssertionError(f"opened for writing: {file} mode={mode}")
            return real_open(file, mode, *args, **kwargs)

        def guarded_os_open(path, flags, *args, **kwargs):
            writes = flags & (
                os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
            )
            if writes and _inside_the_config_dir(path):
                raise AssertionError(f"opened for writing: {path!r} flags={flags}")
            return real_os_open(path, flags, *args, **kwargs)

        monkeypatch.setattr(builtins, "open", guarded_open)
        monkeypatch.setattr(io, "open", guarded_open)
        monkeypatch.setattr(os, "open", guarded_os_open)

        with pytest.raises(ValueError, match="is unchanged"):
            module.add_suppression_to_config(config_path, AshSuppression(**NEW))

        monkeypatch.undo()
        assert config_path.read_bytes() == before
        assert [p.name for p in tmp_path.iterdir()] == [config_path.name]

    def test_a_save_keeps_the_files_place_mode_and_kind(self, tmp_path: Path):
        """The path still names a regular file with its mode kept after the
        save, and no staged leftover sits beside it. The mode assertion is
        skipped on Windows, where chmod only toggles read-only."""
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text("global_settings:\n  suppressions: []\n")
        if os.name != "nt":
            config_path.chmod(0o640)

        assert add_suppression_to_config(config_path, AshSuppression(**NEW)) is True

        assert config_path.is_file() and not config_path.is_symlink()
        if os.name != "nt":
            assert config_path.stat().st_mode & 0o777 == 0o640
        assert _rules(config_path) == ["NEW-1"]
        assert [p.name for p in tmp_path.iterdir()] == [config_path.name]

    def test_a_staged_copy_that_reads_back_wrong_is_never_published(
        self, tmp_path: Path, monkeypatch
    ):
        """The staged copy is read back before it replaces the config. A read
        that returns other bytes than were written (here, a skewed read of the
        staged file alone) is refused in the save's own form, and the config
        keeps its bytes, its mode and its inode: the replace never ran, so the
        path still names the very file it named before. Nothing staged is left
        beside it."""
        config_path = tmp_path / ".ash.yaml"
        before = ("global_settings:\n  suppressions:\n" + OLD_BLOCK).encode("utf-8")
        config_path.write_bytes(before)
        if os.name != "nt":
            config_path.chmod(0o640)
        earlier = config_path.stat()

        real_read_bytes = Path.read_bytes
        skewed: list = []

        def read_bytes(self: Path) -> bytes:
            data = real_read_bytes(self)
            staged = (
                self.parent == tmp_path
                and self.name.startswith(f".{config_path.name}.")
                and self.name.endswith(".tmp")
            )
            if not staged:
                return data
            skewed.append(self)
            return data + b"# skewed\n"

        monkeypatch.setattr(Path, "read_bytes", read_bytes)

        with pytest.raises(ValueError) as refused:
            add_suppression_to_config(config_path, AshSuppression(**NEW))

        monkeypatch.undo()
        message = str(refused.value)
        # The control: the skew fired, on the staged copy and nothing else.
        assert len(skewed) == 1, skewed
        assert "did not read back as written" in message, message
        assert message.endswith(f"{config_path} is unchanged"), message
        assert config_path.read_bytes() == before
        after = config_path.stat()
        assert after.st_ino == earlier.st_ino
        if os.name != "nt":
            assert after.st_mode == earlier.st_mode
        assert [p.name for p in tmp_path.iterdir()] == [config_path.name]

    def test_a_write_that_runs_out_of_space_leaves_the_config_as_it_was(
        self, tmp_path: Path, monkeypatch
    ):
        """A write cut short (a full disk, say) leaves the config with its
        earlier bytes and nothing beside it. The failure is injected at every
        route a file is written through -- the open builtin, io.open (which
        Path.write_bytes uses) and os.fdopen -- with a handle that writes half
        of what it is given and then fails, so a writer that wrote the live
        file in place by any of them would leave it cut short."""
        import builtins
        import errno
        import io

        config_path = tmp_path / ".ash.yaml"
        before = ("global_settings:\n  suppressions:\n" + OLD_BLOCK).encode("utf-8")
        config_path.write_bytes(before)

        class _RunsOutOfSpace:
            def __init__(self, handle):
                self._handle = handle

            def write(self, data):
                self._handle.write(data[: max(1, len(data) // 2)])
                self._handle.flush()
                raise OSError(errno.ENOSPC, "No space left on device")

            def __getattr__(self, name):
                return getattr(self._handle, name)

            def __enter__(self):
                return self

            def __exit__(self, *exc_info):
                self._handle.close()
                return False

        def _writes(mode: object) -> bool:
            return any(letter in str(mode) for letter in "wax+")

        def _ours(file: object) -> bool:
            if isinstance(file, int):
                return True
            try:
                return (
                    Path(os.fsdecode(file)).resolve().is_relative_to(tmp_path.resolve())
                )
            except (TypeError, ValueError):
                return False

        real_open = builtins.open
        real_fdopen = os.fdopen

        def failing_open(file, mode="r", *args, **kwargs):
            handle = real_open(file, mode, *args, **kwargs)
            if _writes(mode) and _ours(file):
                return _RunsOutOfSpace(handle)
            return handle

        def failing_fdopen(fd, mode="r", *args, **kwargs):
            handle = real_fdopen(fd, mode, *args, **kwargs)
            return _RunsOutOfSpace(handle) if _writes(mode) else handle

        monkeypatch.setattr(builtins, "open", failing_open)
        monkeypatch.setattr(io, "open", failing_open)
        monkeypatch.setattr(os, "fdopen", failing_fdopen)

        with pytest.raises(OSError) as failed:
            add_suppression_to_config(config_path, AshSuppression(**NEW))

        monkeypatch.undo()
        assert failed.value.errno == errno.ENOSPC, failed.value
        assert config_path.read_bytes() == before
        assert [p.name for p in tmp_path.iterdir()] == [config_path.name]

    def test_a_config_the_process_may_not_write_is_refused_unchanged(
        self, tmp_path: Path
    ):
        """A config its owner made read-only is refused before anything is
        staged, in the save's own form. The replace of a staged file needs
        only the directory, so without the check the save would succeed and
        bypass the file's own mode. The file keeps its bytes, its mode and
        its inode: the very file the owner protected is still there."""
        if os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0):
            pytest.skip("a file mode does not bind root, and Windows has no mode bits")
        config_path = tmp_path / ".ash.yaml"
        before = ("global_settings:\n  suppressions:\n" + OLD_BLOCK).encode("utf-8")
        config_path.write_bytes(before)
        config_path.chmod(0o444)
        earlier = config_path.stat()

        with pytest.raises(ValueError) as refused:
            add_suppression_to_config(config_path, AshSuppression(**NEW))

        message = str(refused.value)
        assert "not writable" in message, message
        assert message.endswith(f"{config_path} is unchanged"), message
        assert config_path.read_bytes() == before
        after = config_path.stat()
        assert after.st_ino == earlier.st_ino
        assert after.st_mode == earlier.st_mode
        assert [p.name for p in tmp_path.iterdir()] == [config_path.name]

    @pytest.mark.skipif(
        os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
        reason="directory modes are POSIX ones, and they do not bind root",
    )
    def test_a_directory_the_save_cannot_stage_in_is_refused_in_the_saves_words(
        self, tmp_path: Path
    ):
        """A writable config in a directory the process may not write: the
        save needs the directory for both the staged file and the replace,
        so this is the deployment's shape, refused in the save's own words
        with the config unchanged - not a raw PermissionError naming the
        random staging file nobody asked for. The config keeps its bytes,
        its mode and its inode, with nothing staged beside it. (This cell
        previously pinned the raw PermissionError; that contract was the
        gap, so it is re-pinned to the refusal.)"""
        config_path = tmp_path / ".ash.yaml"
        before = ("global_settings:\n  suppressions:\n" + OLD_BLOCK).encode("utf-8")
        config_path.write_bytes(before)
        earlier = config_path.stat()
        saved_mode = tmp_path.stat().st_mode & 0o7777
        os.chmod(tmp_path, 0o555)

        try:
            with pytest.raises(
                ValueError, match="directory is not writable"
            ) as refused:
                add_suppression_to_config(config_path, AshSuppression(**NEW))
        finally:
            os.chmod(tmp_path, saved_mode)

        message = str(refused.value)
        assert message.endswith(f"{config_path} is unchanged"), message
        assert config_path.read_bytes() == before
        after = config_path.stat()
        assert after.st_ino == earlier.st_ino
        assert after.st_mode == earlier.st_mode
        assert [p.name for p in tmp_path.iterdir()] == [config_path.name]

    def test_a_replace_the_directory_refuses_is_refused_in_the_saves_words(
        self, tmp_path: Path, monkeypatch
    ):
        """A directory can let this process stage a file and still refuse the
        replace. The deployment's shape again, so the save answers in its own
        words with the config unchanged and the staged file removed - not a
        raw PermissionError naming the staging file. The refusal used to name
        a sticky directory for EVERY PermissionError here, but a sticky
        directory is only one cause (an open handle on Windows, an immutable
        attribute, an LSM denial are others), so a refusal from this
        ordinary, non-sticky directory stays neutral - and neutral means
        blaming nothing: the cause can be the file itself (an immutable
        attribute, an open handle), so the wording names the system's
        refusal, not the directory. The mislabel sent an operator auditing
        directory modes that were never the problem."""
        config_path = tmp_path / ".ash.yaml"
        before = ("global_settings:\n  suppressions:\n" + OLD_BLOCK).encode("utf-8")
        config_path.write_bytes(before)

        real_replace = os.replace

        def refused_replace(src, dst, *args, **kwargs):
            if Path(str(dst)) == config_path:
                raise PermissionError(1, "Operation not permitted")
            return real_replace(src, dst, *args, **kwargs)

        monkeypatch.setattr(os, "replace", refused_replace)

        with pytest.raises(
            ValueError, match="the system refused to replace the file"
        ) as refused:
            add_suppression_to_config(config_path, AshSuppression(**NEW))

        monkeypatch.undo()
        message = str(refused.value)
        # The refusal's own words end at "; <path> is unchanged", and the
        # path is pytest's directory, named after the test: assertions about
        # the wording read only the head, so a path that happens to contain
        # "sticky" can never satisfy them.
        head = message.split("; ", 1)[0]
        assert " (a sticky directory)" not in head, message
        # The system's own reason rides along (strerror alone - the filename
        # would name the staging file), so the neutral refusal still tells
        # the operator what the OS said.
        assert "(Operation not permitted)" in head, message
        assert message.endswith(f"{config_path} is unchanged"), message
        assert refused.value.__context__ is None, refused.value.__context__
        assert config_path.read_bytes() == before
        assert [p.name for p in tmp_path.iterdir()] == [config_path.name]

    @pytest.mark.skipif(os.name == "nt", reason="file modes are POSIX ones")
    def test_a_replace_a_sticky_directory_refuses_names_the_sticky_bit(
        self, tmp_path: Path, monkeypatch
    ):
        """The control for the neutral wording above: when the config's
        directory really carries the sticky bit (a shared, /tmp-like one,
        which lets only the file's owner replace a file) AND the sticky bit
        can be the cause - the process owns neither the file nor the
        directory and is not root - the refusal names it, because there the
        directory's mode IS what the operator must look at. The test owns
        both, so the effective uid is read as a foreign one; without that,
        the bit cannot constrain this process and the neutral wording is the
        right one (the cell below). The wording is asserted as the exact
        phrase on the text before the path: pytest names tmp_path after the
        test, so this test's own path contains "sticky", and a bare
        ``match="sticky"`` passed even when the refusal was neutral.
        S_ISVTX is a POSIX mode bit, so the measurement - like the other
        mode cells in this file - is skipped on Windows, where the neutral
        wording of the cell above is the only one this refusal uses."""
        shared = tmp_path / "shared"
        shared.mkdir()
        os.chmod(shared, 0o1777)
        config_path = shared / ".ash.yaml"
        before = ("global_settings:\n  suppressions:\n" + OLD_BLOCK).encode("utf-8")
        config_path.write_bytes(before)

        real_replace = os.replace
        foreign_uid = os.geteuid() + 1

        def refused_replace(src, dst, *args, **kwargs):
            if Path(str(dst)) == config_path:
                monkeypatch.setattr(os, "geteuid", lambda: foreign_uid)
                raise PermissionError(1, "Operation not permitted")
            return real_replace(src, dst, *args, **kwargs)

        monkeypatch.setattr(os, "replace", refused_replace)

        with pytest.raises(ValueError, match="is unchanged") as refused:
            add_suppression_to_config(config_path, AshSuppression(**NEW))

        monkeypatch.undo()
        message = str(refused.value)
        head = message.split("; ", 1)[0]
        assert " (a sticky directory)" in head, message
        assert message.endswith(f"{config_path} is unchanged"), message
        assert refused.value.__context__ is None, refused.value.__context__
        assert config_path.read_bytes() == before
        assert [p.name for p in shared.iterdir()] == [config_path.name]

    @pytest.mark.skipif(os.name == "nt", reason="file modes are POSIX ones")
    def test_a_sticky_directory_refusal_on_an_owned_config_stays_neutral(
        self, tmp_path: Path, monkeypatch
    ):
        """The sticky bit blocks a rename over an existing entry only when
        the effective uid owns neither that entry nor the directory and is
        not privileged. This process owns both (it made them), so a
        PermissionError here - an immutable attribute, an LSM denial in a
        shared /tmp - cannot be the sticky bit's doing, and naming "a sticky
        directory" sent an operator auditing a mode that was never the
        problem. The refusal stays neutral and keeps the system's own
        reason."""
        shared = tmp_path / "shared"
        shared.mkdir()
        os.chmod(shared, 0o1777)
        config_path = shared / ".ash.yaml"
        before = ("global_settings:\n  suppressions:\n" + OLD_BLOCK).encode("utf-8")
        config_path.write_bytes(before)

        real_replace = os.replace

        def refused_replace(src, dst, *args, **kwargs):
            if Path(str(dst)) == config_path:
                raise PermissionError(1, "Operation not permitted")
            return real_replace(src, dst, *args, **kwargs)

        monkeypatch.setattr(os, "replace", refused_replace)

        with pytest.raises(
            ValueError, match="the system refused to replace the file"
        ) as refused:
            add_suppression_to_config(config_path, AshSuppression(**NEW))

        monkeypatch.undo()
        message = str(refused.value)
        head = message.split("; ", 1)[0]
        assert " (a sticky directory)" not in head, message
        assert "(Operation not permitted)" in head, message
        assert config_path.read_bytes() == before
        assert [p.name for p in shared.iterdir()] == [config_path.name]

    @pytest.mark.skipif(os.name == "nt", reason="file modes are POSIX ones")
    def test_a_privileged_process_gets_the_neutral_wording(
        self, tmp_path: Path, monkeypatch
    ):
        """Root replaces a file in a sticky directory whoever owns the entry
        (rename(2)), so for a privileged process the bit cannot be what
        refused the replace and the refusal stays neutral with the system's
        own reason. The effective uid is faked only once the replace was
        denied, so the save's own earlier reads stay real. This pins the
        privilege arm of the live path: the save's refusal consults the
        effective uid, and a privileged one keeps the neutral wording. The
        owner arms are staged the same way below, by faking only the reads
        the refusal makes after the deny; the predicate's own matrix pins
        every arm besides."""
        shared = tmp_path / "shared"
        shared.mkdir()
        os.chmod(shared, 0o1777)
        config_path = shared / ".ash.yaml"
        before = ("global_settings:\n  suppressions:\n" + OLD_BLOCK).encode("utf-8")
        config_path.write_bytes(before)

        real_replace = os.replace

        def refused_replace(src, dst, *args, **kwargs):
            if Path(str(dst)) == config_path:
                monkeypatch.setattr(os, "geteuid", lambda: 0)
                raise PermissionError(1, "Operation not permitted")
            return real_replace(src, dst, *args, **kwargs)

        monkeypatch.setattr(os, "replace", refused_replace)

        with pytest.raises(ValueError, match="is unchanged") as refused:
            add_suppression_to_config(config_path, AshSuppression(**NEW))

        monkeypatch.undo()
        message = str(refused.value)
        head = message.split("; ", 1)[0]
        assert " (a sticky directory)" not in head, message
        assert "(Operation not permitted)" in head, message
        assert config_path.read_bytes() == before
        assert [p.name for p in shared.iterdir()] == [config_path.name]

    def _refusal_with_fakes(self, tmp_path: Path, monkeypatch, euid: int, dir_uid_of):
        """The replace denied with the refusal-time reads faked: the effective
        uid and the directory's fresh stat, which the refusal reads after the
        deny and nowhere else. The config's earlier stat stays real, owned by
        this process, as in the privileged cell above."""
        shared = tmp_path / "shared"
        shared.mkdir()
        os.chmod(shared, 0o1777)
        config_path = shared / ".ash.yaml"
        before = ("global_settings:\n  suppressions:\n" + OLD_BLOCK).encode("utf-8")
        config_path.write_bytes(before)
        shared_resolved = shared.resolve()
        real_replace = os.replace
        real_stat = Path.stat
        denied: list = []

        def fake_stat(path_self, *args, **kwargs):
            status = real_stat(path_self, *args, **kwargs)
            if denied and Path(path_self) == shared_resolved:
                fields = list(status)
                fields[4] = dir_uid_of(os.geteuid())
                fields[0] = stat.S_IFDIR | 0o1777
                return os.stat_result(tuple(fields))
            return status

        def refused_replace(src, dst, *args, **kwargs):
            if Path(str(dst)) == config_path.resolve():
                denied.append(True)
                monkeypatch.setattr(os, "geteuid", lambda: euid)
                raise PermissionError(1, "Operation not permitted")
            return real_replace(src, dst, *args, **kwargs)

        monkeypatch.setattr(os, "replace", refused_replace)
        monkeypatch.setattr(Path, "stat", fake_stat)
        with pytest.raises(ValueError, match="is unchanged") as refused:
            add_suppression_to_config(config_path, AshSuppression(**NEW))
        monkeypatch.undo()
        assert denied, "control: the replace was never denied"
        assert config_path.read_bytes() == before
        return str(refused.value)

    @pytest.mark.skipif(os.name == "nt", reason="file modes are POSIX ones")
    def test_the_live_path_stays_neutral_for_the_configs_own_owner(
        self, tmp_path: Path, monkeypatch
    ):
        """Entry-owner arm on the live path: the effective uid owns the config
        (its real earlier stat) and not the directory (whose refusal-time stat
        names another owner), so the bit cannot be what refused the replace."""
        me = os.geteuid()
        message = self._refusal_with_fakes(
            tmp_path, monkeypatch, euid=me, dir_uid_of=lambda fake_euid: me + 2
        )
        head = message.split("; ", 1)[0]
        assert " (a sticky directory)" not in head, message
        assert "(Operation not permitted)" in head, message

    @pytest.mark.skipif(os.name == "nt", reason="file modes are POSIX ones")
    def test_the_live_path_stays_neutral_for_the_directorys_own_owner(
        self, tmp_path: Path, monkeypatch
    ):
        """Directory-owner arm: the effective uid (another one, read at
        refusal time) owns the directory (its refusal-time stat) and not the
        config (whose real earlier stat names this process)."""
        other = os.geteuid() + 1
        message = self._refusal_with_fakes(
            tmp_path, monkeypatch, euid=other, dir_uid_of=lambda fake_euid: fake_euid
        )
        head = message.split("; ", 1)[0]
        assert " (a sticky directory)" not in head, message
        assert "(Operation not permitted)" in head, message

    @pytest.mark.skipif(os.name == "nt", reason="file modes are POSIX ones")
    def test_control_the_same_fakes_name_the_bit_for_a_foreign_owner(
        self, tmp_path: Path, monkeypatch
    ):
        """Positive control through the same seam: a foreign effective uid
        that owns neither the config nor the refusal-time directory gets the
        sticky wording, so the two neutral cells above measure the owner
        arms, not the fakes."""
        me = os.geteuid()
        message = self._refusal_with_fakes(
            tmp_path, monkeypatch, euid=me + 1, dir_uid_of=lambda fake_euid: me + 2
        )
        head = message.split("; ", 1)[0]
        assert " (a sticky directory)" in head, message

    @pytest.mark.skipif(os.name == "nt", reason="file modes are POSIX ones")
    def test_a_sticky_directory_refusal_on_a_new_config_stays_neutral(
        self, tmp_path: Path, monkeypatch
    ):
        """A new config has no directory entry for the sticky bit to
        protect, so even a process that owns nothing here is not constrained
        by the bit: a refused replace of a brand-new file in a sticky
        directory keeps the neutral wording, foreign effective uid and
        all."""
        shared = tmp_path / "shared"
        shared.mkdir()
        os.chmod(shared, 0o1777)
        config_path = shared / ".ash.yaml"
        assert not config_path.exists()

        real_replace = os.replace
        foreign_uid = os.geteuid() + 1

        def refused_replace(src, dst, *args, **kwargs):
            if Path(str(dst)) == config_path:
                monkeypatch.setattr(os, "geteuid", lambda: foreign_uid)
                raise PermissionError(1, "Operation not permitted")
            return real_replace(src, dst, *args, **kwargs)

        monkeypatch.setattr(os, "replace", refused_replace)

        with pytest.raises(
            ValueError, match="the system refused to replace the file"
        ) as refused:
            add_suppression_to_config(config_path, AshSuppression(**NEW))

        monkeypatch.undo()
        message = str(refused.value)
        head = message.split("; ", 1)[0]
        assert " (a sticky directory)" not in head, message
        assert "(Operation not permitted)" in head, message
        assert not config_path.exists()
        assert [p.name for p in shared.iterdir()] == []

    @pytest.mark.skipif(os.name == "nt", reason="the predicate reads POSIX uids")
    def test_the_sticky_cause_predicate_reads_ownership_and_privilege(
        self, monkeypatch
    ):
        """The arms a real filesystem cannot stage without root, pinned on
        the predicate itself with synthetic stat results: the sticky bit is
        named only when there is an entry to protect, the directory's mode
        carries the bit, and the effective uid is neither 0 nor either
        owner. The effective uid is pinned to a fixed non-zero value and
        every fixture uid derives from it, so the cell measures the
        predicate the same way under any real uid: under a root CI leg the
        real uid is 0, which made the positive arm fail and let the
        ownership arms pass by privilege instead of ownership. On Windows
        os.geteuid does not exist and no directory is sticky, so a missing
        geteuid answers False."""
        from automated_security_helper.config.ash_config import (
            _sticky_refusal_applies,
        )

        euid = 1000
        monkeypatch.setattr(os, "geteuid", lambda: euid)

        def result(mode: int, uid: int) -> os.stat_result:
            return os.stat_result((mode, 0, 0, 1, uid, 0, 0, 0, 0, 0))

        sticky_dir = result(stat.S_IFDIR | 0o1777, euid + 2)
        plain_dir = result(stat.S_IFDIR | 0o777, euid + 2)
        foreign_file = result(stat.S_IFREG | 0o644, euid + 1)

        assert _sticky_refusal_applies(foreign_file, sticky_dir) is True
        # No entry to protect: a new config.
        assert _sticky_refusal_applies(None, sticky_dir) is False
        # The bit is not set.
        assert _sticky_refusal_applies(foreign_file, plain_dir) is False
        # The process owns the file.
        owned_file = result(stat.S_IFREG | 0o644, euid)
        assert _sticky_refusal_applies(owned_file, sticky_dir) is False
        # The process owns the directory.
        owned_dir = result(stat.S_IFDIR | 0o1777, euid)
        assert _sticky_refusal_applies(foreign_file, owned_dir) is False
        # Privilege: root (approximating CAP_FOWNER) replaces anything,
        # sticky or not.
        monkeypatch.setattr(os, "geteuid", lambda: 0)
        assert _sticky_refusal_applies(foreign_file, sticky_dir) is False
        monkeypatch.undo()
        # Windows: no geteuid, no sticky semantics.
        monkeypatch.delattr(os, "geteuid")
        assert _sticky_refusal_applies(foreign_file, sticky_dir) is False

    @pytest.mark.skipif(os.name == "nt", reason="file modes are POSIX ones")
    def test_a_new_config_is_created_without_opening_the_process_umask(
        self, tmp_path: Path, monkeypatch
    ):
        """A new config gets the mode a plain create gives it, and the save
        never widens the process-wide umask to get there: another thread's
        file created in that moment would be made world-writable. Every file
        created while the save calls os.umask is checked for the mode the
        process's own umask gives."""
        mask = os.umask(0o022)
        os.umask(mask)
        expected = oct(0o666 & ~mask)
        probes = tmp_path / "meanwhile"
        probes.mkdir()
        created_meanwhile: list = []
        real_umask = os.umask

        def creates_a_file_meanwhile(value):
            previous = real_umask(value)
            probe = probes / f"probe-{len(created_meanwhile)}"
            descriptor = os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)
            os.close(descriptor)
            created_meanwhile.append(oct(probe.stat().st_mode & 0o777))
            probe.unlink()
            return previous

        monkeypatch.setattr(os, "umask", creates_a_file_meanwhile)
        config_path = tmp_path / ".ash.yaml"

        assert add_suppression_to_config(config_path, AshSuppression(**NEW)) is True

        monkeypatch.undo()
        assert all(mode == expected for mode in created_meanwhile), created_meanwhile
        assert oct(config_path.stat().st_mode & 0o777) == expected

    @pytest.mark.skipif(not hasattr(os, "fchown"), reason="file owners are POSIX ones")
    def test_a_save_gives_the_config_its_earlier_owner(
        self, tmp_path: Path, monkeypatch
    ):
        """The replaced file carries the earlier file's owner and group, as
        far as the process may set them: a save by root (sudo, a root
        container) would otherwise leave a user's config owned by root. The
        file that takes the owner is the one the replace publishes."""
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text("global_settings:\n  suppressions: []\n")
        status = config_path.stat()
        given: list = []
        real_fchown = os.fchown

        def recording_fchown(fd, uid, gid):
            given.append((os.fstat(fd).st_ino, uid, gid))
            return real_fchown(fd, uid, gid)

        monkeypatch.setattr(os, "fchown", recording_fchown)

        assert add_suppression_to_config(config_path, AshSuppression(**NEW)) is True

        monkeypatch.undo()
        published = config_path.stat()
        assert (published.st_ino, status.st_uid, status.st_gid) in given, given
        assert (published.st_uid, published.st_gid) == (status.st_uid, status.st_gid)

    @pytest.mark.skipif(not hasattr(os, "fchown"), reason="file owners are POSIX ones")
    def test_an_owner_the_process_may_not_set_does_not_stop_the_save(
        self, tmp_path: Path, monkeypatch
    ):
        """Copying the owner is best effort: a process that may not give the
        file the earlier owner (a user saving a config another user owns, in
        a directory the user may write) still saves it."""
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text("global_settings:\n  suppressions: []\n")
        refused: list = []

        def refusing_fchown(fd, uid, gid):
            refused.append((uid, gid))
            raise PermissionError(1, "Operation not permitted")

        monkeypatch.setattr(os, "fchown", refusing_fchown)

        assert add_suppression_to_config(config_path, AshSuppression(**NEW)) is True

        monkeypatch.undo()
        # The control: the owner copy was attempted, and refused.
        assert refused, refused
        assert _rules(config_path) == ["NEW-1"]
        assert [p.name for p in tmp_path.iterdir()] == [config_path.name]

    def test_the_staged_bytes_reach_the_disk_before_they_replace_the_config(
        self, tmp_path: Path, monkeypatch
    ):
        """The staged file is flushed to the disk before the replace publishes
        it, and the directory after: on a filesystem that does not order the
        data before the rename, a power loss could otherwise leave the config
        empty. Measured as the order of the calls, and by the inode: the file
        synced is the file the replace publishes."""
        import stat as stat_module

        config_path = tmp_path / ".ash.yaml"
        config_path.write_text("global_settings:\n  suppressions: []\n")
        events: list = []
        real_fsync = os.fsync
        real_replace = os.replace

        def recording_fsync(fd):
            status = os.fstat(fd)
            kind = "dir" if stat_module.S_ISDIR(status.st_mode) else "file"
            events.append(("fsync", kind, status.st_ino))
            return real_fsync(fd)

        def recording_replace(src, dst, *args, **kwargs):
            events.append(("replace",))
            return real_replace(src, dst, *args, **kwargs)

        monkeypatch.setattr(os, "fsync", recording_fsync)
        monkeypatch.setattr(os, "replace", recording_replace)

        assert add_suppression_to_config(config_path, AshSuppression(**NEW)) is True

        monkeypatch.undo()
        assert ("replace",) in events, events
        at = events.index(("replace",))
        published = config_path.stat().st_ino
        assert ("fsync", "file", published) in events[:at], events
        if os.name != "nt":
            # A directory cannot be opened to sync on Windows.
            parent = tmp_path.stat().st_ino
            assert ("fsync", "dir", parent) in events[at:], events

    @pytest.mark.skipif(not hasattr(os, "fchown"), reason="file owners are POSIX ones")
    def test_a_group_the_save_cannot_keep_gets_none_of_the_mode(
        self, tmp_path: Path, monkeypatch
    ):
        """When neither fchown form keeps the earlier file's group, the staged
        file keeps the saver's group, and the earlier mode's group bits would
        open the file to a group its owner did not give them to: the applied
        mode drops them."""
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text("global_settings:\n  suppressions: []\n")
        config_path.chmod(0o640)
        refused: list = []

        def refusing_fchown(fd, uid, gid):
            refused.append((uid, gid))
            raise PermissionError(1, "Operation not permitted")

        monkeypatch.setattr(os, "fchown", refusing_fchown)

        assert add_suppression_to_config(config_path, AshSuppression(**NEW)) is True

        monkeypatch.undo()
        # The control: both forms, with the owner and group-only, were refused.
        assert len(refused) == 2, refused
        import stat as stat_module

        mode = stat_module.S_IMODE(config_path.stat().st_mode)
        assert mode == 0o600, oct(mode)

    def test_the_staged_file_is_named_as_a_staging_file(
        self, tmp_path: Path, monkeypatch
    ):
        """A crash between the stage and the replace (a kill, a power loss)
        leaves the staged file behind, so its name says what it is: the
        shape utils/atomic_write.py stages with, ``.<name>.<pid>.<hex>.tmp``,
        which readers and cleanups recognize as temporary."""
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text("global_settings:\n  suppressions: []\n")
        staged_names: list = []
        real_replace = os.replace

        def recording_replace(src, dst, *args, **kwargs):
            staged_names.append(Path(src).name)
            return real_replace(src, dst, *args, **kwargs)

        monkeypatch.setattr(os, "replace", recording_replace)

        assert add_suppression_to_config(config_path, AshSuppression(**NEW)) is True

        monkeypatch.undo()
        assert staged_names, staged_names
        for name in staged_names:
            assert name.startswith(f".{config_path.name}.{os.getpid()}."), name
            assert name.endswith(".tmp"), name
        assert [p.name for p in tmp_path.iterdir()] == [config_path.name]

    def test_an_existing_file_s_staged_copy_starts_no_wider_than_private(
        self, tmp_path: Path, monkeypatch
    ):
        """The staged copy of an existing file is created private (0o600 at
        most, before the earlier mode is applied), so no reader sees the new
        bytes under a wider mode between the create and the fchmod. The umask
        is pinned to 0o022 for the save: under a 0o077 umask a 0o666 create
        also comes out 0o600, and the cell could not tell the two apart."""
        import stat as stat_module

        from automated_security_helper.config import ash_config as module

        config_path = tmp_path / ".ash.yaml"
        config_path.write_text("global_settings:\n  suppressions: []\n")
        config_path.chmod(0o600)
        at_creation: list = []
        real_give = module._give_earlier_owner_and_mode

        def sampling_give(descriptor, earlier):
            at_creation.append(stat_module.S_IMODE(os.fstat(descriptor).st_mode))
            return real_give(descriptor, earlier)

        monkeypatch.setattr(module, "_give_earlier_owner_and_mode", sampling_give)

        mask = os.umask(0o022)
        try:
            saved = add_suppression_to_config(config_path, AshSuppression(**NEW))
        finally:
            os.umask(mask)

        assert saved is True
        monkeypatch.undo()
        # The control: the staged copy was sampled at creation.
        assert at_creation, at_creation
        assert all(mode & ~0o600 == 0 for mode in at_creation), [
            oct(mode) for mode in at_creation
        ]

    @pytest.mark.skipif(
        os.name == "nt",
        reason="creating a symlink needs a privilege or Developer Mode there",
    )
    def test_a_symlinked_config_stays_a_symlink(self, tmp_path: Path):
        """A config that is a symlink keeps being one: its target takes the
        entry and stays a regular file. A rename over the path itself would
        put a regular file where the link was."""
        target = tmp_path / "shared" / "ash.yaml"
        target.parent.mkdir()
        target.write_text("global_settings:\n  suppressions: []\n")
        config_path = tmp_path / ".ash.yaml"
        config_path.symlink_to(target)

        assert add_suppression_to_config(config_path, AshSuppression(**NEW)) is True

        assert config_path.is_symlink()
        assert target.is_file() and not target.is_symlink()
        assert _rules(target) == ["NEW-1"]

    @pytest.mark.skipif(
        os.name == "nt",
        reason="creating a symlink needs a privilege or Developer Mode there",
    )
    def test_a_dangling_link_to_a_missing_directory_survives_a_failed_save(
        self, tmp_path: Path
    ):
        """A save through a symlink whose target's directory does not exist
        fails with the system's own error, and the user's link is kept exactly
        as it was, pointing where it pointed: a failed save deletes nothing it
        did not create."""
        config_path = tmp_path / ".ash.yaml"
        pointed = tmp_path / "gone" / "ash.yaml"
        config_path.symlink_to(pointed)

        with pytest.raises(OSError):
            add_suppression_to_config(config_path, AshSuppression(**NEW))

        assert config_path.is_symlink()
        assert os.readlink(str(config_path)) == str(pointed)
        assert not pointed.exists()

    def test_a_staged_copy_that_reads_back_differently_is_refused(
        self, tmp_path: Path, monkeypatch
    ):
        """The staged bytes are read back and compared before the replace; a
        copy that answers different bytes (a lying filesystem, a concurrent
        writer on the staging name) refuses the save with the config kept.
        Pins the read-back compare itself: with it turned off, the corrupted
        copy would replace the user's config."""
        config_path = tmp_path / ".ash.yaml"
        before = "global_settings:\n  suppressions: []\n"
        config_path.write_text(before, encoding="utf-8")
        real_read_bytes = Path.read_bytes

        def lying_read_bytes(self):
            data = real_read_bytes(self)
            if self.name.startswith("..ash.yaml.") and self.name.endswith(".tmp"):
                return data + b"# corrupted\n"
            return data

        monkeypatch.setattr(Path, "read_bytes", lying_read_bytes)

        with pytest.raises(ValueError, match="is unchanged") as refused:
            add_suppression_to_config(config_path, AshSuppression(**NEW))

        assert "did not read back as written" in str(refused.value), refused.value
        monkeypatch.undo()
        assert config_path.read_text(encoding="utf-8") == before
        leftovers = sorted(p.name for p in tmp_path.iterdir() if p.name != ".ash.yaml")
        assert leftovers == [], leftovers

    @pytest.mark.skipif(
        not hasattr(os, "fchown"), reason="fchown is this cell's refused call"
    )
    def test_a_refused_fchown_drops_the_group_bits_and_saves(
        self, tmp_path: Path, monkeypatch
    ):
        """A process that may set neither owner nor group still saves: the
        refusal is logged and the earlier mode's group bits (and setgid) are
        dropped, so the staged file's own group is not given bits its owner
        never granted it. Pins the fallback itself: with the except arm
        removed, the refused fchown would fail the whole save."""
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text(
            "global_settings:\n  suppressions: []\n", encoding="utf-8"
        )
        os.chmod(config_path, 0o640)

        def refused(*args, **kwargs):
            raise PermissionError("fchown is not permitted here")

        monkeypatch.setattr(os, "fchown", refused)

        assert add_suppression_to_config(config_path, AshSuppression(**NEW)) is True

        assert _rules(config_path) == ["NEW-1"]
        assert config_path.stat().st_mode & 0o777 == 0o600

    def test_a_config_mounted_as_a_single_file_is_refused_in_the_saves_words(
        self, tmp_path: Path, monkeypatch
    ):
        """``os.replace`` cannot replace a mount point, so a config mounted as
        one file (a container's single-file volume) answers EBUSY. The save
        refuses in its own words, with the config unchanged and the staged
        copy removed, instead of a raw OSError naming an internal staging
        file the user never heard of. Every other OSError stays raw: the
        staged path in those messages is the path the OS refused."""
        import errno

        config_path = tmp_path / ".ash.yaml"
        before = "global_settings:\n  suppressions: []\n"
        config_path.write_text(before, encoding="utf-8")

        def busy(source, target, *args, **kwargs):
            raise OSError(
                errno.EBUSY, "Device or resource busy", str(source), None, str(target)
            )

        monkeypatch.setattr(os, "replace", busy)

        with pytest.raises(ValueError, match="is unchanged") as refused:
            add_suppression_to_config(config_path, AshSuppression(**NEW))

        text = str(refused.value)
        assert "mounted as a single file" in text, text
        assert ".tmp" not in text, text
        assert config_path.read_text(encoding="utf-8") == before
        leftovers = sorted(p.name for p in tmp_path.iterdir() if p.name != ".ash.yaml")
        assert leftovers == [], leftovers


# YAML's line breaks besides CR and LF: NEL, and the line and paragraph
# separators. str.splitlines and PyYAML both end a line at each. They are
# written with chr(), so this file holds no invisible characters.
_YAML_OTHER_LINE_BREAKS = [
    pytest.param(chr(0x85), id="next-line"),
    pytest.param(chr(0x2028), id="line-separator"),
    pytest.param(chr(0x2029), id="paragraph-separator"),
]


def _invisible_code_points(text: str) -> list:
    """The code points in *text* a reader cannot see, as ``U+XXXX``, sorted:
    category Cf (format controls, the BOM included), Zl and Zp (the line and
    paragraph separators), Cc (the C0 and C1 controls, NEL and ESC among
    them) other than the tab, LF and CR a source file holds as its layout,
    Zs other than the plain space (spaces that read as one), the Hangul
    fillers, which draw nothing, and a named list of blank-drawing code
    points outside those categories: the braille pattern blank and the
    musical symbol null notehead (So), and the combining grapheme joiner,
    the variation selectors in both planes (U+FE00..U+FE0F and the
    supplement U+E0100..U+E01EF), the Mongolian free variation selectors
    (the vowel separator between them, U+180E, is Cf and already swept)
    and the Khmer inherent vowels (Mn). So and Mn are still not swept
    whole, because visible symbols and legitimate combining marks live
    there."""
    import unicodedata

    layout = ("\t", "\n", "\r")
    fillers = (chr(0x115F), chr(0x1160), chr(0x3164), chr(0xFFA0))
    blank_drawing = (
        chr(0x2800),
        chr(0x034F),
        chr(0x17B4),
        chr(0x17B5),
        chr(0x1D159),
        *(chr(point) for point in range(0xFE00, 0xFE10)),
        chr(0x180B),
        chr(0x180C),
        chr(0x180D),
        chr(0x180F),
        *(chr(point) for point in range(0xE0100, 0xE01F0)),
    )
    return sorted(
        f"U+{ord(character):04X}"
        for character in set(text)
        if unicodedata.category(character) in ("Cf", "Zl", "Zp")
        or (unicodedata.category(character) == "Cc" and character not in layout)
        or (unicodedata.category(character) == "Zs" and character != " ")
        or character in fillers
        or character in blank_drawing
    )


def _sources_promising_no_invisible_characters() -> list:
    """The files whose own comments promise they hold no invisible
    characters: this one (above _YAML_OTHER_LINE_BREAKS), ash_config.py
    (above _OTHER_YAML_BREAKS), get_scan_set.py (above _UTF8_BOM) and the
    byte-order-mark test module (above U_FEFF)."""
    from automated_security_helper.config import ash_config
    from automated_security_helper.utils import get_scan_set

    return [
        pytest.param(Path(__file__), id="this-test-file"),
        pytest.param(Path(ash_config.__file__), id="ash-config-module"),
        pytest.param(Path(get_scan_set.__file__), id="get-scan-set-module"),
        pytest.param(
            Path(__file__).parent.parent
            / "utils"
            / "test_ignore_file_byte_order_mark_in_any_encoding.py",
            id="byte-order-mark-test-file",
        ),
    ]


@pytest.mark.parametrize(
    "promising_source", _sources_promising_no_invisible_characters()
)
def test_each_source_promising_no_invisible_characters_spells_them_with_chr(
    promising_source: Path,
):
    """Each file whose comment promises it holds no invisible characters is
    read here, and a raw one is exactly what a reader cannot see: a BOM
    inside a string literal reads as an empty position, and an editor or a
    diff can drop or duplicate it silently. Every such code point is spelled
    ``chr(0x...)`` instead. This cell is the promises' guard: each file's
    own source holds no code point _invisible_code_points names."""
    source = promising_source.read_text(encoding="utf-8")
    assert _invisible_code_points(source) == [], _invisible_code_points(source)


@pytest.mark.parametrize(
    "planted",
    [
        pytest.param(chr(0x85), id="next-line"),
        pytest.param(chr(0x2028), id="line-separator"),
        pytest.param(chr(0x2029), id="paragraph-separator"),
        pytest.param(chr(0xFEFF), id="byte-order-mark"),
        pytest.param(chr(0x1B), id="escape"),
    ],
)
def test_the_invisible_character_guard_names_each_break_the_file_spells(planted):
    """The guard above reads its own file, which holds none of these, so it
    cannot show by itself that it would see one. Each is planted in a text of
    its own here: the three YAML breaks the comment above names (NEL is a C0/C1
    control, not a separator, so a category check for separators alone passes
    it), the BOM, and ESC."""
    assert _invisible_code_points("a" + planted + "b") == [f"U+{ord(planted):04X}"]


@pytest.mark.parametrize(
    "planted",
    [
        pytest.param(chr(0xA0), id="no-break-space"),
        pytest.param(chr(0x1680), id="ogham-space-mark"),
        pytest.param(chr(0x2007), id="figure-space"),
        pytest.param(chr(0x205F), id="medium-mathematical-space"),
        pytest.param(chr(0x202F), id="narrow-no-break-space"),
        pytest.param(chr(0x3000), id="ideographic-space"),
        pytest.param(chr(0x3164), id="hangul-filler"),
        pytest.param(chr(0x115F), id="hangul-choseong-filler"),
        pytest.param(chr(0x1160), id="hangul-jungseong-filler"),
        pytest.param(chr(0xFFA0), id="halfwidth-hangul-filler"),
    ],
)
def test_the_invisible_character_guard_names_each_space_that_reads_as_a_plain_one(
    planted,
):
    """A space other than the plain one reads exactly like it, so a string
    literal holding one compares unequal to the text it shows; the Hangul
    fillers draw nothing at all. Each is planted in a text of its own. The
    Ogham space mark and the medium mathematical space are here because a
    guard that merely listed the other four literals would pass them: the
    rule has to be the Zs category itself."""
    assert _invisible_code_points("a" + planted + "b") == [f"U+{ord(planted):04X}"]


@pytest.mark.parametrize(
    "planted",
    [
        pytest.param(chr(0x2800), id="braille-pattern-blank"),
        pytest.param(chr(0x034F), id="combining-grapheme-joiner"),
        pytest.param(chr(0xFE00), id="variation-selector-1"),
        pytest.param(chr(0xFE0F), id="variation-selector-16"),
        pytest.param(chr(0x17B4), id="khmer-vowel-inherent-aq"),
        pytest.param(chr(0x17B5), id="khmer-vowel-inherent-aa"),
        pytest.param(chr(0x180B), id="mongolian-free-variation-selector-one"),
        pytest.param(chr(0x180C), id="mongolian-free-variation-selector-two"),
        pytest.param(chr(0x180D), id="mongolian-free-variation-selector-three"),
        pytest.param(chr(0x180F), id="mongolian-free-variation-selector-four"),
        pytest.param(chr(0xE0100), id="variation-selector-17"),
        pytest.param(chr(0xE01EF), id="variation-selector-256"),
        pytest.param(chr(0x1D159), id="musical-symbol-null-notehead"),
    ],
)
def test_the_invisible_character_guard_names_each_blank_drawing_code_point(planted):
    """A handful of code points outside the swept categories draw nothing:
    the braille pattern with no dots raised and the musical null notehead
    (symbols, So), and the combining grapheme joiner, the variation
    selectors, and the Khmer inherent vowels (combining marks, Mn). The
    guard names them from its own list, because sweeping So or Mn whole
    would flag visible symbols and legitimate combining marks. Each is
    planted in a text of its own. The two runs the list builds as ranges
    are pinned by both of their ends: the variation selectors by U+FE00
    and U+FE0F, and their supplement by U+E0100 and U+E01EF. Every point
    the list names on its own is planted: the braille blank, the joiner,
    the null notehead, both Khmer inherent vowels, and all four Mongolian
    free variation selectors, U+180B, U+180C, U+180D and U+180F, which the
    list names one by one because U+180E between them is Cf and already
    swept."""
    assert _invisible_code_points("a" + planted + "b") == [f"U+{ord(planted):04X}"]


def test_the_invisible_character_guard_passes_the_whitespace_source_holds():
    """Tab, LF and CR are controls too, and a source file holds them as its
    own layout, as it holds the plain space: the guard names none of them."""
    assert _invisible_code_points("a\tb\nc\r\nd e") == []


class TestTheSaveKeepsEverythingElseTheFileHeld:
    """A save changes the suppressions list and nothing else: the document it
    would write, with the new entry taken out, must equal the one the file
    held. Checking only the suppressions let a save that dropped every other
    setting report success."""

    @pytest.mark.parametrize(
        "head",
        [
            '"global_settings":',
            "global_settings :",
            chr(0xFEFF) + "global_settings:",
        ],
        ids=["quoted-key", "space-before-colon", "utf8-bom"],
    )
    def test_a_save_keeps_every_setting_the_file_held(self, tmp_path: Path, head: str):
        """global_settings written in a spelling the line scan does not take
        for the key: a second global_settings block appended after it would
        be the one YAML keeps, and the file's own settings would be gone."""
        config_path = tmp_path / ".ash.yaml"
        before = head + "\n  severity_threshold: HIGH\n  fail_on_findings: false\n"
        config_path.write_bytes(before.encode("utf-8"))

        try:
            saved = add_suppression_to_config(config_path, AshSuppression(**NEW))
        except ValueError as refused:
            assert "is unchanged" in str(refused), refused
            saved = False

        after = config_path.read_bytes()
        settings = _global_settings(config_path)
        assert settings.get("severity_threshold") == "HIGH", (saved, after)
        assert settings.get("fail_on_findings") is False, (saved, after)
        if saved:
            assert _rules(config_path) == ["NEW-1"], after
        else:
            assert after == before.encode("utf-8")

    def test_a_reason_that_looks_like_an_env_reference_reloads_literally(
        self, tmp_path: Path, monkeypatch
    ):
        """A saved reason is the operator's literal text when it is read back.
        The loader tags a PLAIN scalar matching its ``${VAR}`` pattern as an
        implicit ``!ENV`` read (allowlist ASH_* and three AWS names), so a
        reason starting ``${ASH_...}`` saved unquoted reloaded with the
        variable's value substituted - the literal text lost, and the value
        then flows wherever the reason prints. Implicit resolvers apply to
        plain scalars only, so the writer quotes such a value and the loader's
        own documented advice ("quote a value that only looks like a ${VAR}
        reference") is what the save produces."""
        from automated_security_helper.config.config_sources import (
            load_config_document,
        )

        monkeypatch.setenv("ASH_SUPPRESSION_PROBE", "resolved-from-env")
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text("project_name: demo\n", encoding="utf-8")
        reason = "${ASH_SUPPRESSION_PROBE} was the operator's literal text"

        saved = add_suppression_to_config(
            config_path,
            AshSuppression(rule_id="NEW-1", path="a.py", reason=reason),
        )

        assert saved is True
        entry = (load_config_document(config_path).get("global_settings") or {})[
            "suppressions"
        ][0]
        assert entry.get("reason") == reason, entry
        assert "resolved-from-env" not in str(entry), entry

    def test_the_control_a_name_the_loader_does_not_read_stays_literal(
        self, tmp_path: Path, monkeypatch
    ):
        """The control: a ``${VAR}`` naming no allowlisted variable is left as
        written by the loader itself (with a notice), so it reloads literally
        with or without the writer's quoting - the previous cell's red is the
        allowlisted name, not ${...} text in general."""
        from automated_security_helper.config.config_sources import (
            load_config_document,
        )

        monkeypatch.setenv("SUPPRESSION_NOT_ALLOWLISTED", "never-read")
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text("project_name: demo\n", encoding="utf-8")
        reason = "${SUPPRESSION_NOT_ALLOWLISTED} stays as written"

        assert (
            add_suppression_to_config(
                config_path,
                AshSuppression(rule_id="NEW-1", path="a.py", reason=reason),
            )
            is True
        )
        entry = (load_config_document(config_path).get("global_settings") or {})[
            "suppressions"
        ][0]
        assert entry.get("reason") == reason, entry
        assert "never-read" not in str(entry), entry

    def test_a_reference_shaped_reason_survives_the_full_rewrite(
        self, tmp_path: Path, monkeypatch
    ):
        """The full-rewrite save (Case D: a shape the text edits cannot
        touch, here an inline ``global_settings`` mapping) protects a
        reference-shaped value the way the text edits above do. The rewrite
        dumped the new entry's reason as a PLAIN scalar, so the next load's
        implicit ``!ENV`` resolver read the environment value into the
        document - flowing wherever the reason prints - where every other
        save path already quoted it."""
        from automated_security_helper.config.config_sources import (
            load_config_document,
        )

        monkeypatch.setenv("ASH_SUPPRESSION_PROBE", "resolved-from-env")
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text("global_settings: {}\n", encoding="utf-8")
        reason = "${ASH_SUPPRESSION_PROBE} was the operator's literal text"

        saved = add_suppression_to_config(
            config_path,
            AshSuppression(rule_id="NEW-1", path="a.py", reason=reason),
        )

        assert saved is True
        entry = (load_config_document(config_path).get("global_settings") or {})[
            "suppressions"
        ][0]
        assert entry.get("reason") == reason, entry
        assert "resolved-from-env" not in str(entry), entry

    @pytest.mark.parametrize(
        "before",
        [
            pytest.param(
                "global_settings:\n  suppressions:\n"
                "    - rule_id: OLD-1\n      path: old.py\n      reason: fine\n",
                id="an-existing-list-case-a",
            ),
            pytest.param(
                "global_settings:\n  severity_threshold: MEDIUM\n",
                id="a-block-without-the-key-case-b",
            ),
        ],
    )
    def test_a_reference_shaped_reason_survives_the_text_edits(
        self, tmp_path: Path, monkeypatch, before: str
    ):
        """The text-edit save paths (an existing list, and a block
        global_settings without the key; the no-global_settings path is the
        cell above these), pinned beside the whole-dump cells below so every
        save path carries this property. One mechanism serves them all: the
        dumper's own str representer, which the text edits reach through
        _serialize_entry_lines - so these cells and the whole-dump ones
        measure the same rule from both sides."""
        from automated_security_helper.config.config_sources import (
            load_config_document,
        )

        monkeypatch.setenv("ASH_SUPPRESSION_PROBE", "resolved-from-env")
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text(before, encoding="utf-8")
        reason = "${ASH_SUPPRESSION_PROBE} was the operator's literal text"

        saved = add_suppression_to_config(
            config_path,
            AshSuppression(rule_id="NEW-1", path="a.py", reason=reason),
        )

        assert saved is True
        entries = (load_config_document(config_path).get("global_settings") or {})[
            "suppressions"
        ]
        assert entries[-1].get("reason") == reason, entries
        assert "resolved-from-env" not in str(entries), entries

    def test_a_reference_shaped_reason_survives_a_brand_new_file(
        self, tmp_path: Path, monkeypatch
    ):
        """The third dump path: a save with no config file at all writes a
        fresh document through the same whole-document dump as the full
        rewrite, so it protected nothing either - the same reason came back
        from the next load as the environment variable's value."""
        from automated_security_helper.config.config_sources import (
            load_config_document,
        )

        monkeypatch.setenv("ASH_SUPPRESSION_PROBE", "resolved-from-env")
        config_path = tmp_path / ".ash.yaml"
        assert not config_path.exists()
        reason = "${ASH_SUPPRESSION_PROBE} was the operator's literal text"

        saved = add_suppression_to_config(
            config_path,
            AshSuppression(rule_id="NEW-1", path="a.py", reason=reason),
        )

        assert saved is True
        entry = (load_config_document(config_path).get("global_settings") or {})[
            "suppressions"
        ][0]
        assert entry.get("reason") == reason, entry
        assert "resolved-from-env" not in str(entry), entry

    def test_a_quoted_reference_elsewhere_survives_the_full_rewrite_quoted(
        self, tmp_path: Path, monkeypatch
    ):
        """A value the operator deliberately quoted so it reloads as its own
        text - here an existing entry's reason - is still quoted after the
        full rewrite. The rewrite read it with ``_KeepsEnvReferences`` (the
        quoted scalar is its text) and dumped it back PLAIN, so one save of
        an unrelated entry turned every such literal in the file back into a
        resolving reference. The dumper's protection is text-shaped
        (ENV_REFERENCE_PATTERN), and its named blind spot is
        ``_KeepsEnvReferences`` itself: a reference carrying an explicit
        ``!ENV`` tag is read as its bare text, which this dump would quote
        into a literal and stop it resolving - those files never reach the
        rewrite, because Case D refuses any file ``uses_env_references``
        answers True for."""
        from automated_security_helper.config.config_sources import (
            load_config_document,
        )

        monkeypatch.setenv("ASH_SUPPRESSION_PROBE", "resolved-from-env")
        config_path = tmp_path / ".ash.yaml"
        kept = "${ASH_SUPPRESSION_PROBE} kept literal"
        config_path.write_text(
            "global_settings: {suppressions: [{rule_id: OLD-1, path: old.py, "
            f"reason: '{kept}'}}]}}\n",
            encoding="utf-8",
        )

        saved = add_suppression_to_config(config_path, AshSuppression(**NEW))

        assert saved is True
        document = load_config_document(config_path)
        entries = (document.get("global_settings") or {})["suppressions"]
        assert entries[0].get("reason") == kept, entries
        assert "resolved-from-env" not in str(document), document
        assert [e.get("rule_id") for e in entries] == ["OLD-1", "NEW-1"], entries

    def test_a_reason_merely_holding_a_dollar_stays_plain(
        self, tmp_path: Path, monkeypatch
    ):
        """The must-not-fire side of the rewrite's quoting: a string that
        holds a ``$`` without the reference shape (ENV_REFERENCE_PATTERN
        anchors at the start and needs ``${word``) is not a reference, is
        never resolved, and stays a plain scalar - the dump does not creep
        toward quoting everything."""
        from automated_security_helper.config.config_sources import (
            load_config_document,
        )

        monkeypatch.setenv("ASH_SUPPRESSION_PROBE", "resolved-from-env")
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text("global_settings: {}\n", encoding="utf-8")
        reason = "$5 of effort, and HOME=$HOME stays text"

        saved = add_suppression_to_config(
            config_path,
            AshSuppression(rule_id="NEW-1", path="a.py", reason=reason),
        )

        assert saved is True
        text = config_path.read_text(encoding="utf-8")
        assert f"reason: {reason}" in text, text
        entry = (load_config_document(config_path).get("global_settings") or {})[
            "suppressions"
        ][0]
        assert entry.get("reason") == reason, entry

    def test_a_comment_on_the_global_settings_line_keeps_every_comment(
        self, tmp_path: Path
    ):
        """A trailing comment on the ``global_settings:`` line is not a value.
        The block reader took anything after the colon for an inline mapping,
        so the save fell through to the whole rewrite, which dropped EVERY
        comment in the file (top-of-file, trailing and in-block alike) and
        reindented the list - user data loss for one stray comment. The save
        inserts as text instead: every line the file held is still there,
        byte for byte, with only the new entry's lines added."""
        config_path = tmp_path / ".ash.yaml"
        before_lines = [
            "# top comment kept\n",
            "project_name: demo  # trailing comment kept\n",
            "global_settings: # the comment on the key line\n",
            "  # a comment inside the block\n",
            "  severity_threshold: MEDIUM  # another kept\n",
        ]
        config_path.write_text("".join(before_lines), encoding="utf-8")

        assert add_suppression_to_config(config_path, AshSuppression(**NEW)) is True

        after = config_path.read_text(encoding="utf-8")
        after_lines = after.splitlines(keepends=True)
        for line in before_lines:
            assert line in after_lines, (line, after)
        # The entry landed, and only its lines were added.
        assert _rules(config_path) == ["NEW-1"], after
        assert _global_settings(config_path)["severity_threshold"] == "MEDIUM"
        added = [line for line in after_lines if line not in before_lines]
        assert all("NEW-1" in line or "a.py" in line or ":" in line for line in added)
        assert len(after_lines) == len(before_lines) + len(added)

    def test_a_save_that_would_add_another_setting_is_refused(
        self, tmp_path: Path, monkeypatch
    ):
        """The comparison covers the whole document, not only the keys a
        repeat would collide on: an edit that slips a setting in beside the
        new entry (here a serialized entry that brings a sibling key with it)
        is refused, and the file keeps its bytes."""
        from automated_security_helper.config import ash_config as module

        real = module._serialize_entry_lines

        def with_a_setting(entry, indent):
            return real(entry, indent) + [f"{indent[:-2]}fail_on_findings: true\n"]

        monkeypatch.setattr(module, "_serialize_entry_lines", with_a_setting)
        config_path = tmp_path / ".ash.yaml"
        before = b"global_settings:\n  severity_threshold: HIGH\n"
        config_path.write_bytes(before)

        with pytest.raises(ValueError, match="setting the file held") as refused:
            module.add_suppression_to_config(config_path, AshSuppression(**NEW))

        assert "is unchanged" in str(refused.value)
        assert config_path.read_bytes() == before

    @pytest.mark.parametrize(
        "before,key",
        [
            (
                "global_settings:\n  suppressions:\n" + OLD_BLOCK + "  suppressions:\n"
                "    - rule_id: OTHER\n      path: other.py\n      reason: kept\n",
                "suppressions",
            ),
            (
                (
                    "global_settings:\n  severity_threshold: HIGH\n"
                    "global_settings:\n  fail_on_findings: false\n"
                ),
                "global_settings",
            ),
        ],
        ids=["two-suppressions-keys", "two-global-settings-blocks"],
    )
    def test_a_refusal_for_a_repeated_key_names_it(
        self, tmp_path: Path, before: str, key: str
    ):
        """YAML keeps only the last of two equal keys, which is why such a
        save cannot hold its entry. The refusal says so, naming the key,
        rather than only that the entry would not be held."""
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text(before, encoding="utf-8")

        with pytest.raises(ValueError, match="is unchanged") as refused:
            add_suppression_to_config(config_path, AshSuppression(**NEW))

        assert f"repeats the key {key!r}" in str(refused.value), refused.value
        assert "only the last" in str(refused.value), refused.value
        assert config_path.read_text(encoding="utf-8") == before

    def test_a_json_config_with_a_repeated_key_is_refused_and_left_alone(
        self, tmp_path: Path
    ):
        """JSON keeps the last of two equal keys too, and the JSON save
        writes the document back whole, so the first block's settings would
        vanish from the file while both parsed documents agree. Refused,
        naming the key, with the file's bytes kept."""
        config_path = tmp_path / ".ash.json"
        before = (
            '{"global_settings": {"severity_threshold": "HIGH"}, '
            '"global_settings": {"fail_on_findings": false}}\n'
        )
        config_path.write_text(before, encoding="utf-8")

        with pytest.raises(ValueError, match="is unchanged") as refused:
            add_suppression_to_config(config_path, AshSuppression(**NEW))

        assert "'global_settings'" in str(refused.value), refused.value
        assert config_path.read_text(encoding="utf-8") == before

    def test_a_json_config_repeating_any_key_is_refused_and_left_alone(
        self, tmp_path: Path
    ):
        """The JSON save writes the parsed document back whole, which keeps
        only the last of two equal keys wherever they sit, not only at the
        keys the save edits: a file repeating any key is refused with its
        bytes kept, so the first block does not silently vanish."""
        config_path = tmp_path / ".ash.json"
        before = (
            '{"scanners": {"bandit": {"enabled": true}}, '
            '"scanners": {"semgrep": {"enabled": true}}, '
            '"global_settings": {"suppressions": []}}\n'
        )
        config_path.write_text(before, encoding="utf-8")

        with pytest.raises(ValueError, match="is unchanged") as refused:
            add_suppression_to_config(config_path, AshSuppression(**NEW))

        assert "repeats" in str(refused.value), refused.value
        assert "'scanners'" in str(refused.value), refused.value
        assert config_path.read_text(encoding="utf-8") == before

    @pytest.mark.parametrize(
        "before",
        [
            pytest.param('{"global_settings": null}\n', id="null-global-settings"),
            pytest.param(
                '{"global_settings": {"suppressions": null}}\n',
                id="null-suppressions",
            ),
        ],
    )
    def test_a_json_null_means_empty_as_it_does_for_yaml(
        self, tmp_path: Path, before: str
    ):
        """The YAML save reads a null global_settings or suppressions as an
        empty one, and the in-memory compare (_apart_from_the_entry) reads
        both formats so. The JSON edit follows the same rule: the entry is
        added where the YAML save would add it, instead of refusing the
        file's own explicit null as 'is not an object' or 'is not a list'."""
        import json as json_module

        config_path = tmp_path / ".ash.json"
        config_path.write_text(before, encoding="utf-8")

        assert add_suppression_to_config(config_path, AshSuppression(**NEW)) is True

        data = json_module.loads(config_path.read_text(encoding="utf-8"))
        entries = data["global_settings"]["suppressions"]
        assert [entry["rule_id"] for entry in entries] == ["NEW-1"], entries

    @pytest.mark.parametrize(
        "before,key",
        [
            pytest.param(
                "scanners:\n"
                "  bandit: {enabled: true}\n"
                "global_settings: {severity_threshold: MEDIUM}\n"
                "scanners:\n"
                "  semgrep: {enabled: true}\n",
                "scanners",
                id="two-top-level-scanners-blocks",
            ),
            pytest.param(
                "global_settings: {severity_threshold: LOW,"
                " severity_threshold: HIGH}\n",
                "severity_threshold",
                id="inside-the-inline-mapping",
            ),
        ],
    )
    def test_a_yaml_whole_rewrite_repeating_any_key_is_refused_and_left_alone(
        self, tmp_path: Path, before: str, key: str
    ):
        """A YAML shape the save cannot edit as text (an inline
        global_settings mapping) is written back whole, as the JSON save is:
        only the last of two equal keys survives, wherever they sit. The same
        input is refused the JSON branch's way, naming the key, with the
        file's bytes kept, instead of the first block silently vanishing
        while both parsed documents agree."""
        config_path = tmp_path / ".ash.yaml"
        config_path.write_text(before, encoding="utf-8")

        with pytest.raises(ValueError, match="is unchanged") as refused:
            add_suppression_to_config(config_path, AshSuppression(**NEW))

        assert f"{key!r}" in str(refused.value), refused.value
        assert "only the last" in str(refused.value), refused.value
        assert config_path.read_text(encoding="utf-8") == before

    @pytest.mark.parametrize("line_break", _YAML_OTHER_LINE_BREAKS)
    def test_a_dash_before_a_yaml_line_break_is_a_block_item(
        self, tmp_path: Path, line_break: str
    ):
        """YAML's other line breaks (NEL, and the line and paragraph
        separators) end a line like a newline does, so a ``-`` followed by
        one is a block item whose value starts on the next line. The line
        readers read only space, tab, CR and LF after the dash, so
        ``_value_line_under_key`` read the dash's line as a value and such a
        file was refused with the misleading "holds its value on the line
        under its key (a flow list or a value)" (measured at the commit this
        cell pinned) - the save must append to it like any other block
        list."""
        config_path = tmp_path / ".ash.yaml"
        before = (
            "global_settings:\n  suppressions:\n"
            f"    -{line_break}      rule_id: OLD-1\n"
            "      path: old.py\n      reason: kept\n"
        )
        config_path.write_text(before, encoding="utf-8")

        assert add_suppression_to_config(config_path, AshSuppression(**NEW)) is True

        text = config_path.read_text(encoding="utf-8")
        assert "NEW-1" in text, text
        assert _rules(config_path) == ["OLD-1", "NEW-1"], text

    @pytest.mark.parametrize("line_break", _YAML_OTHER_LINE_BREAKS)
    def test_a_dash_before_a_yaml_line_break_at_the_keys_indent_is_a_block_item(
        self, tmp_path: Path, line_break: str
    ):
        """YAML lets a block sequence sit at its key's own indent, so the same
        ``-`` item there is an item too. The under-key value check stops at a
        line at the key's indent, so only the append-point scan reads this
        shape: the entry goes after the item, at its indent, and every byte
        the file held stays."""
        config_path = tmp_path / ".ash.yaml"
        before = (
            "global_settings:\n  suppressions:\n"
            f"  -{line_break}    rule_id: OLD-1\n"
            "    path: old.py\n    reason: kept\n"
        )
        config_path.write_bytes(before.encode("utf-8"))

        assert add_suppression_to_config(config_path, AshSuppression(**NEW)) is True

        text = config_path.read_bytes().decode("utf-8")
        assert text.startswith(before), text
        assert text[len(before) :].startswith("  - "), text
        assert _rules(config_path) == ["OLD-1", "NEW-1"], text

    @pytest.mark.parametrize("line_break", _YAML_OTHER_LINE_BREAKS)
    @pytest.mark.parametrize("value", ["[]", "~"], ids=["empty-flow-list", "null"])
    def test_an_empty_list_ended_by_a_yaml_line_break_takes_the_entry(
        self, tmp_path: Path, monkeypatch, value: str, line_break: str
    ):
        """The same breaks after the colon: a ``suppressions: []`` or ``~``
        line ended by one holds no entry, as one ended by a newline does, so
        the value goes and the entry goes under the key. The line's ending
        was read as CR and LF only, so such a file was refused as "written on
        its key's line", a cause it does not have. The line keeps its own
        break, the sibling key stays after the list, and the scan's loader
        reads the entry from the saved file."""
        monkeypatch.delenv("ASH_CONFIG", raising=False)
        config_path = tmp_path / ".ash.yaml"
        before = (
            "project_name: p\nglobal_settings:\n"
            f"  suppressions: {value}{line_break}  severity_threshold: MEDIUM\n"
        )
        config_path.write_bytes(before.encode("utf-8"))

        assert add_suppression_to_config(config_path, AshSuppression(**NEW)) is True

        text = config_path.read_bytes().decode("utf-8")
        assert text.startswith(
            f"project_name: p\nglobal_settings:\n  suppressions:{line_break}"
        ), text
        assert text.endswith("  severity_threshold: MEDIUM\n"), text
        assert _rules(config_path) == ["NEW-1"], text
        assert _global_settings(config_path)["severity_threshold"] == "MEDIUM"
        _, config = load_config_file(config_path)
        assert [
            (s.rule_id, s.path, s.reason) for s in config.global_settings.suppressions
        ] == [("NEW-1", "a.py", "pinned")]

    @pytest.mark.parametrize("line_break", _YAML_OTHER_LINE_BREAKS)
    def test_the_empty_list_pattern_stops_at_a_break_before_a_final_newline(
        self, line_break: str
    ):
        """The pattern's old ``$`` anchor also matches before a string-final
        LF, so a key line ending in one of YAML's other breaks WITH a newline
        after it matched as though the break were the text's end. The save
        cannot hand the pattern such text (its one caller passes elements of
        ``str.splitlines``, where a break is only ever the last character),
        but the pattern must say what its caller means: an accepted ending is
        the LAST thing in the text, nothing after it."""
        from automated_security_helper.config.ash_config import (
            _EMPTY_SUPPRESSIONS_LINE,
        )

        text = f"  suppressions: []{line_break}\n"
        assert _EMPTY_SUPPRESSIONS_LINE.match(text) is None, repr(text)

    @pytest.mark.parametrize(
        "line_break",
        ["\r", *_YAML_OTHER_LINE_BREAKS],
        ids=["cr", "next-line", "line-separator", "paragraph-separator"],
    )
    def test_the_empty_list_pattern_keeps_the_comment_on_one_line(
        self, line_break: str
    ):
        """The comment group was ``#.*``, and ``.`` crosses CR, NEL and the
        line and paragraph separators, so a "comment" spanning what YAML
        reads as two lines matched, with the second line's text swallowed
        into the comment. Unreachable through the save for the same
        splitlines reason, and wrong as written: a comment runs to its
        line's end, so the group stops at every line break."""
        from automated_security_helper.config.ash_config import (
            _EMPTY_SUPPRESSIONS_LINE,
        )

        text = f"  suppressions: [] # a{line_break}b"
        assert _EMPTY_SUPPRESSIONS_LINE.match(text) is None, repr(text)

    def test_a_tab_separated_block_item_is_refused_in_the_parsers_words(
        self, tmp_path: Path
    ):
        """YAML forbids a tab where a token starts, so a ``-<TAB>rule_id:``
        item never parses: the save refuses the file as unparseable, naming
        the parser's error and where (not its prose, which can quote file
        content), before any line reader judges its shape. The two line readers
        (the under-key value check and the append-point scan) both read a
        ``-`` followed by a tab as a block item (_a_block_item), so there is
        no parseable file on which they disagree - this cell pins the parser
        boundary that keeps that true."""
        config_path = tmp_path / ".ash.yaml"
        before = (
            "global_settings:\n  suppressions:\n"
            "    -\trule_id: OLD-1\n    \tpath: old.py\n"
        )
        config_path.write_text(before, encoding="utf-8")

        with pytest.raises(ValueError, match="is unchanged") as refused:
            add_suppression_to_config(config_path, AshSuppression(**NEW))

        assert "could not be parsed" in str(refused.value), refused.value
        assert "ScannerError at line 3, column 6" in str(refused.value), refused.value
        assert config_path.read_text(encoding="utf-8") == before

    @pytest.mark.parametrize(
        "before,key",
        [
            pytest.param(
                '{"scanners": {"bandit": {"options": '
                '{"confidence": "LOW", "confidence": "HIGH"}}}, '
                '"global_settings": {"suppressions": []}}\n',
                "confidence",
                id="in-a-scanner-s-options",
            ),
            pytest.param(
                '{"global_settings": {"suppressions": [{"rule_id": "OLD", '
                '"path": "old.py", "reason": "kept", "reason": "replaced"}]}}\n',
                "reason",
                id="in-a-suppression-entry",
            ),
            pytest.param(
                '{"global_settings": {"suppressions": [], "suppressions": '
                '[{"rule_id": "OLD", "path": "old.py", "reason": "kept"}]}}\n',
                "suppressions",
                id="suppressions-inside-global-settings",
            ),
        ],
    )
    def test_a_json_config_repeating_a_key_below_the_top_is_refused(
        self, tmp_path: Path, before: str, key: str
    ):
        """The same for a repeat below the top level: the whole-document write
        keeps only the last of two equal keys at any depth, in a scanner's
        options, inside a suppression entry, or the suppressions key itself."""
        config_path = tmp_path / ".ash.json"
        config_path.write_text(before, encoding="utf-8")

        with pytest.raises(ValueError, match="is unchanged") as refused:
            add_suppression_to_config(config_path, AshSuppression(**NEW))

        assert "repeats" in str(refused.value), refused.value
        assert f"'{key}'" in str(refused.value), refused.value
        assert config_path.read_text(encoding="utf-8") == before


class TestAShapeTheSuppressionCannotGoInIsRefusedByName:
    """A parsed value where the list cannot live is refused with a ValueError
    that names the place and says the file is unchanged, rather than crashing
    on the shape or refusing in another check's words."""

    def test_a_global_settings_that_is_not_a_mapping_is_refused(self, tmp_path: Path):
        """``global_settings: "suppressions:[]"`` is a string: there is no
        block to put a list in, and reading keys off it would crash."""
        config_path = tmp_path / ".ash.yaml"
        before = 'global_settings: "suppressions:[]"\n'
        config_path.write_text(before, encoding="utf-8")

        with pytest.raises(ValueError, match="is unchanged") as refused:
            add_suppression_to_config(config_path, AshSuppression(**NEW))

        assert "global_settings" in str(refused.value), refused.value
        assert "mapping" in str(refused.value), refused.value
        assert config_path.read_text(encoding="utf-8") == before

    def test_a_suppressions_value_that_is_not_a_list_is_refused(self, tmp_path: Path):
        """A mapping under the suppressions key is not a list an entry can be
        appended to; the refusal says so instead of reporting the appended
        text as a parse failure."""
        config_path = tmp_path / ".ash.yaml"
        before = "global_settings:\n  suppressions:\n    broken: true\n"
        config_path.write_text(before, encoding="utf-8")

        with pytest.raises(ValueError, match="is unchanged") as refused:
            add_suppression_to_config(config_path, AshSuppression(**NEW))

        assert "suppressions" in str(refused.value), refused.value
        assert "list" in str(refused.value), refused.value
        assert config_path.read_text(encoding="utf-8") == before

    def test_the_key_line_refusal_says_the_file_is_unchanged(self, tmp_path: Path):
        """The inline-value refusal ends the same way the checked write's
        refusals do, so a caller reads the same promise from each."""
        config_path = tmp_path / ".ash.yaml"
        before = "global_settings:\n  suppressions: [1, 2]\n"
        config_path.write_text(before, encoding="utf-8")

        with pytest.raises(ValueError, match="key's line") as refused:
            add_suppression_to_config(config_path, AshSuppression(**NEW))

        assert "is unchanged" in str(refused.value), refused.value
        assert config_path.read_text(encoding="utf-8") == before

    def test_the_reference_rewrite_refusal_says_the_file_is_unchanged(
        self, tmp_path: Path, monkeypatch
    ):
        """The same for the full-rewrite refusal of a file that reads values
        from the environment."""
        monkeypatch.setenv("ASH_PROBE_PROJECT", "probe")
        config_path = tmp_path / ".ash.yaml"
        before = (
            "project_name: ${ASH_PROBE_PROJECT}\n"
            "global_settings: {severity_threshold: MEDIUM}\n"
        )
        config_path.write_text(before, encoding="utf-8")

        with pytest.raises(ValueError, match="by hand") as refused:
            add_suppression_to_config(config_path, AshSuppression(**NEW))

        assert "is unchanged" in str(refused.value), refused.value
        assert config_path.read_text(encoding="utf-8") == before

    @pytest.mark.parametrize(
        "name,before,which",
        [
            pytest.param(
                ".ash.yaml", b"project_name: \xff\n", "not UTF-8", id="yaml-not-utf8"
            ),
            pytest.param(
                ".ash.yaml",
                b"project_name: [unclosed\n",
                "could not be parsed",
                id="yaml-does-not-parse",
            ),
            pytest.param(
                ".ash.yaml",
                b"project_name: t\nextends: base.yaml\n",
                "extends another config",
                id="yaml-extends",
            ),
            pytest.param(
                ".ash.json",
                b'{"project_name": "\xff"}\n',
                "not UTF-8",
                id="json-not-utf8",
            ),
            pytest.param(
                ".ash.json",
                b'{"project_name": \n',
                "could not be parsed",
                id="json-does-not-parse",
            ),
            pytest.param(
                ".ash.json",
                b"[]\n",
                "does not hold a JSON object",
                id="json-not-an-object",
            ),
            pytest.param(
                ".ash.json",
                b'{"global_settings": []}\n',
                "is not an object",
                id="json-global-settings-not-an-object",
            ),
            pytest.param(
                ".ash.json",
                b'{"extends": "base.json"}\n',
                "extends another config",
                id="json-extends",
            ),
            pytest.param(
                ".ash.json",
                b'{"global_settings": {"suppressions": {}}}\n',
                "is not a list",
                id="json-suppressions-not-a-list",
            ),
            pytest.param(".ash.toml", b'project_name = "t"\n', "is TOML", id="toml"),
        ],
    )
    def test_every_refusal_before_the_write_says_the_file_is_unchanged(
        self, tmp_path: Path, name: str, before: bytes, which: str
    ):
        """Each refusal the save makes before writing anything ends with the
        same promise as the checked write's: the path, and that it is
        unchanged. A caller reads one wording, whichever check refused."""
        config_path = tmp_path / name
        config_path.write_bytes(before)

        with pytest.raises(ValueError) as refused:
            add_suppression_to_config(config_path, AshSuppression(**NEW))

        message = str(refused.value)
        # The control: the intended check refused it.
        assert which in message, message
        assert message.endswith(f"{config_path} is unchanged"), message
        assert config_path.read_bytes() == before

    def test_a_path_that_is_not_a_regular_file_says_it_is_unchanged(
        self, tmp_path: Path
    ):
        """The not-a-regular-file refusal comes from the readers' shared check
        (refuse_unless_a_file), whose wording is its own. Through the save it
        carries the same closing promise as every other refusal, so the dialog
        that shows the save's errors reads one wording here too."""
        config_path = tmp_path / ".ash.yaml"
        config_path.mkdir()

        with pytest.raises(ValueError) as refused:
            add_suppression_to_config(config_path, AshSuppression(**NEW))

        message = str(refused.value)
        # The control: the shared check's own words refused it.
        assert "is not a regular file" in message, message
        assert message.endswith(f"{config_path} is unchanged"), message
        assert config_path.is_dir() and not any(config_path.iterdir())

    def test_a_path_that_is_not_a_regular_file_is_refused_with_no_chained_error(
        self, tmp_path: Path
    ):
        """The save's refusal is raised after the shared check's handler, not
        inside it, so a traceback of the refusal shows one error and not the
        shared check's beneath it."""
        config_path = tmp_path / ".ash.yaml"
        config_path.mkdir()

        with pytest.raises(ValueError) as refused:
            add_suppression_to_config(config_path, AshSuppression(**NEW))

        # The control: the shared check refused it, in the save's form.
        assert "is not a regular file" in str(refused.value), refused.value
        assert refused.value.__cause__ is None, refused.value.__cause__
        assert refused.value.__context__ is None, refused.value.__context__


# The byte order mark some Windows editors write (PowerShell 5.1's
# Set-Content -Encoding UTF8, VS Code's "UTF-8 with BOM").
_MARK = chr(0xFEFF)


class TestAMarkedOrDecoratedFileTakesTheEntry:
    """Shapes the file's loader reads as the one global_settings block, written
    in text the line scan read as something else: a leading UTF-8 byte order
    mark, an anchor or tag between the key and its block list, and a null
    value where ``[]`` already takes the entry. Each is a config the scan
    loads, so the save takes the entry rather than refusing it."""

    def test_a_file_with_a_byte_order_mark_takes_the_entry(self, tmp_path: Path):
        """YAML reads past the mark, so the marked line holds the file's one
        global_settings block: the entry is appended into its list, and the
        written file keeps the mark."""
        config_path = tmp_path / ".ash.yaml"
        before = _MARK + (
            "global_settings:\n"
            "  severity_threshold: MEDIUM\n"
            "  suppressions:\n" + OLD_BLOCK
        )
        config_path.write_bytes(before.encode("utf-8"))

        assert add_suppression_to_config(config_path, AshSuppression(**NEW))

        after = config_path.read_bytes()
        assert after.startswith(_MARK.encode("utf-8")), after[:8]
        assert _global_settings(config_path).get("severity_threshold") == "MEDIUM", (
            after
        )
        assert _rules(config_path) == ["OLD", "NEW-1"], after

    def test_a_marked_file_without_a_list_gets_one_in_its_block(self, tmp_path: Path):
        """The marked file holds settings and no suppressions key. The key and
        entry go inside the block the scan loads, not a second top-level
        global_settings, so severity_threshold is in the loaded config
        beside the entry."""
        config_path = tmp_path / ".ash.yaml"
        before = _MARK + "global_settings:\n  severity_threshold: MEDIUM\n"
        config_path.write_bytes(before.encode("utf-8"))

        assert add_suppression_to_config(config_path, AshSuppression(**NEW))

        after = config_path.read_bytes()
        assert after.startswith(_MARK.encode("utf-8")), after[:8]
        text = after.decode("utf-8")
        assert text.count("global_settings:") == 1, text
        assert _global_settings(config_path).get("severity_threshold") == "MEDIUM", (
            after
        )
        assert _rules(config_path) == ["NEW-1"], after

    @pytest.mark.parametrize("decoration", ["&shared", "!!seq"], ids=["anchor", "tag"])
    def test_a_decorated_block_list_takes_the_entry(
        self, tmp_path: Path, decoration: str
    ):
        """An anchor or tag alone after the key names or types the node below
        it, which here is the block list: the entry is appended to that list
        and the decoration stays in the file."""
        config_path = tmp_path / ".ash.yaml"
        before = f"global_settings:\n  suppressions: {decoration}\n" + OLD_BLOCK
        config_path.write_text(before, encoding="utf-8")

        assert add_suppression_to_config(config_path, AshSuppression(**NEW))

        text = config_path.read_text(encoding="utf-8")
        assert decoration in text, text
        assert _rules(config_path) == ["OLD", "NEW-1"], text

    @pytest.mark.parametrize("spelled", ["~", "null"], ids=["tilde", "word"])
    def test_a_null_suppressions_value_takes_the_entry(
        self, tmp_path: Path, spelled: str
    ):
        """``suppressions: ~`` holds no list, as ``[]`` holds an empty one:
        the value goes, the comment stays, and the entry is the list's first
        block item."""
        config_path = tmp_path / ".ash.yaml"
        before = f"global_settings:\n  suppressions: {spelled} # none yet\n"
        config_path.write_text(before, encoding="utf-8")

        assert add_suppression_to_config(config_path, AshSuppression(**NEW))

        text = config_path.read_text(encoding="utf-8")
        assert "# none yet" in text, text
        assert _rules(config_path) == ["NEW-1"], text

    def test_an_anchor_followed_by_a_value_is_still_refused(self, tmp_path: Path):
        """The control: an anchor with a flow list after it on the key's line
        is a value a block item cannot follow."""
        config_path = tmp_path / ".ash.yaml"
        before = (
            "global_settings:\n"
            "  suppressions: &shared [{rule_id: OLD, path: old.py, reason: kept}]\n"
        )
        config_path.write_text(before, encoding="utf-8")

        with pytest.raises(ValueError, match="key's line"):
            add_suppression_to_config(config_path, AshSuppression(**NEW))

        assert config_path.read_text(encoding="utf-8") == before

    def test_a_list_read_again_through_an_alias_is_refused(self, tmp_path: Path):
        """Appending to an anchored list the document reads again through an
        alias would change that other setting with it. The whole-document
        compare refuses the save, and the file keeps its bytes."""
        config_path = tmp_path / ".ash.yaml"
        before = (
            "global_settings:\n"
            "  suppressions: &shared\n" + OLD_BLOCK + "reporters:\n"
            "  stub:\n"
            "    options:\n"
            "      mirror: *shared\n"
        )
        config_path.write_text(before, encoding="utf-8")

        with pytest.raises(ValueError, match="is unchanged"):
            add_suppression_to_config(config_path, AshSuppression(**NEW))

        assert config_path.read_text(encoding="utf-8") == before
