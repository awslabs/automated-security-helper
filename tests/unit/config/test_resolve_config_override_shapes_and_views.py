# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""resolve_config's override parsing, discovery gate, operator views and
overlay handling, on the shapes that mangled a value, read ungated or warned
about a chain that was fine.

- find_config_file gated the discovery candidates in one pass and ran discovery
  ungated in another.
- An append override onto a list field the document lacks became a plain set.
- A bracketed value that is not JSON was split at every comma; true, false and
  null were recognized only without surrounding whitespace; a str option could
  not be set to "true" or "null".
- An override with no '=' was echoed whole in the refusal, value included.
- validate_config_document and the overlay validated without the context
  build_config passes.
- _operator_chain_occurrences read the overlay's chain appended to the
  selected one as a tree that could not be rebuilt.
- The overlay refusal and the honor_ignore_files warning named a file an
  extends entry chose with an environment value by its path.
- operator_config_digest read each file with an unbounded read_bytes; the
  overlay test used Path.is_file, which raises under an unsearchable parent.
- _CONFINED_SANDBOX_SETTINGS named two of the four lists the confinement
  replaces; _operator_paths resolved the ASH_CONFIG chain a second time.
"""

from __future__ import annotations

import hashlib
import logging
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.config import resolve_config as module
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.resolve_config import (
    _CONFINED_SANDBOX_SETTINGS,
    _apply_config_override,
    _load_overlay,
    _operator_chain_occurrences,
    _operator_paths,
    _parse_config_value,
    apply_config_overrides,
    confine_honor_ignore_files,
    find_config_file,
    operator_config_digest,
    split_config_override,
    validate_config_document,
)
from automated_security_helper.core.exceptions import (
    ASHConfigSourceError,
    ASHConfigValidationError,
)

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _environment(monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


class TestFindConfigFile:
    def test_discovery_runs_under_the_callers_gate(self, tmp_path, monkeypatch):
        seen = {}

        def spy(search_dir, permit=None):
            seen["permit"] = permit
            return SimpleNamespace(selected=None)

        monkeypatch.setattr(module, "discover_config_source", spy)

        def permit(path: Path) -> bool:
            return True

        assert find_config_file(tmp_path, permit=permit) is None
        assert seen["permit"] is permit


class TestApplyConfigOverride:
    def test_an_append_starts_a_list_the_document_lacks(self):
        document: dict = {}
        keys, value, appended = _apply_config_override(
            document, "ash_plugin_modules+", "x"
        )
        assert document == {"ash_plugin_modules": ["x"]}
        assert appended is True

    def test_an_append_onto_none_starts_the_list(self):
        document = {"ash_plugin_modules": None}
        _apply_config_override(document, "ash_plugin_modules+", "[a, b]")
        assert document == {"ash_plugin_modules": ["a", "b"]}

    def test_control_an_append_onto_a_list_extends_it(self):
        document = {"ash_plugin_modules": ["a"]}
        _apply_config_override(document, "ash_plugin_modules+", "b")
        assert document == {"ash_plugin_modules": ["a", "b"]}


class TestParseConfigValue:
    @pytest.mark.parametrize(
        ("value", "parsed"),
        [
            pytest.param("['a, b', 'c']", ["a, b", "c"], id="quoted-comma"),
            pytest.param("[[1, 2], [3]]", [[1, 2], [3]], id="nested"),
            pytest.param("true ", True, id="true-trailing-blank"),
            pytest.param("null\r", None, id="null-carriage-return"),
            pytest.param("False", False, id="control-false"),
            pytest.param("[a, b]", ["a", "b"], id="control-bare-list"),
        ],
    )
    def test_values_parse_as_written(self, value, parsed):
        assert _parse_config_value(value) == parsed

    def test_a_str_option_takes_the_words_true_and_null(self):
        config = apply_config_overrides(AshConfig(), ["project_name=true"])
        assert config.project_name == "true"
        config = apply_config_overrides(AshConfig(), ["project_name=null"])
        assert config.project_name == "null"


class TestOverrideRefusal:
    def test_an_entry_with_no_separator_is_not_echoed_when_it_is_not_a_key(self):
        with pytest.raises(ASHConfigValidationError) as refused:
            split_config_override("qz secret value 5531")
        text = str(refused.value)
        assert "qz secret" not in text and "5531" not in text, text
        assert "not shown" in text and "key.path=value" in text, text

    def test_control_a_key_typed_alone_is_quoted(self):
        with pytest.raises(ASHConfigValidationError) as refused:
            split_config_override("no-equals")
        assert "Invalid config override: 'no-equals'" in str(refused.value)

    def test_apply_config_overrides_names_no_value_either(self):
        with pytest.raises(ASHConfigValidationError) as refused:
            apply_config_overrides(AshConfig(), ["qz secret value 5531"])
        assert "5531" not in str(refused.value), str(refused.value)

    @pytest.mark.parametrize(
        "entry",
        [
            "ab12" * 10,  # a 40-hex digest is key-shaped but not a key
            "QZEXAMPLEKEYIDQZ0000",  # an access-key-shaped id: bare, 20 long
            "scanners.qz.token98765",  # a digit run of five inside a key path
            "qz.key.path." * 3 + "name",  # a key-shaped entry past 32 chars
        ],
    )
    def test_a_token_shaped_entry_with_no_separator_is_not_echoed(self, entry):
        with pytest.raises(ASHConfigValidationError) as refused:
            split_config_override(entry)
        text = str(refused.value)
        assert entry not in text, text
        assert f"an entry of {len(entry)} characters with no '=' (not shown)" in text

    @pytest.mark.parametrize(
        "entry", ["no-equals", "scanners.bandit.enabled", "qz_option-2", "a1b2c3"]
    )
    def test_control_a_short_key_shaped_word_is_still_quoted(self, entry):
        with pytest.raises(ASHConfigValidationError) as refused:
            split_config_override(entry)
        assert f"Invalid config override: '{entry}'" in str(refused.value)

    @pytest.mark.parametrize(("entry", "key"), [("=renamed", ""), ("  =renamed", "  ")])
    def test_a_blank_key_before_an_equals_is_quoted_as_the_key(self, entry, key):
        """An entry with an '=' is named by its key part, never by what follows
        the '=', and never as "no '='"; the two CLI paths read the same."""
        with pytest.raises(ASHConfigValidationError) as split:
            split_config_override(entry)
        with pytest.raises(ASHConfigValidationError) as applied:
            apply_config_overrides(AshConfig(), [entry])
        expected = f"Invalid config override: '{key}'. Expected format: key.path=value"
        assert str(split.value) == expected, str(split.value)
        assert str(applied.value) == expected, str(applied.value)
        assert "renamed" not in str(split.value)


class TestValidateConfigDocument:
    def test_the_file_load_context_is_passed(self, monkeypatch, tmp_path):
        seen = {}
        original = AshConfig.model_validate

        def spy(data, **kwargs):
            seen.update(kwargs)
            return original(data, **kwargs)

        monkeypatch.setattr(AshConfig, "model_validate", spy)
        document = SimpleNamespace(data={"project_name": "p"}, environment_values=[])
        validate_config_document(document, tmp_path / "ash.yaml")
        assert seen.get("context") == {"strict_file_load": True}
        assert seen.get("strict") is True


class TestOperatorChainOccurrences:
    def test_two_appended_trees_are_both_walked(self, tmp_path, caplog):
        base = tmp_path / "base.yaml"
        root = tmp_path / "root.yaml"
        overlay = tmp_path / "overlay.yaml"
        for path in (base, root, overlay):
            path.write_text("project_name: p\n", encoding="utf-8")
        reads = {
            base.resolve(): {"project_name": "b"},
            root.resolve(): {"extends": "base.yaml", "project_name": "r"},
            overlay.resolve(): {"project_name": "o"},
        }
        with caplog.at_level(logging.WARNING):
            owned = _operator_chain_occurrences(
                [base, root, overlay], [], reads, frozenset(), roots=2
            )
        assert owned == [base, root, overlay]
        assert "could not be rebuilt" not in caplog.text

    def test_control_a_count_past_the_stack_is_not_rebuilt(self, tmp_path, caplog):
        root = tmp_path / "root.yaml"
        root.write_text("project_name: p\n", encoding="utf-8")
        reads = {root.resolve(): {"extends": ["a.yaml", "b.yaml"]}}
        with caplog.at_level(logging.WARNING):
            assert _operator_chain_occurrences([root], [], reads, frozenset()) == []
        assert "could not be rebuilt" in caplog.text


class TestHonorIgnoreFilesWarning:
    def test_an_environment_chosen_file_is_named_value(self, tmp_path, caplog):
        base = tmp_path / "qzbase-7731.yaml"
        base.write_text("honor_ignore_files: false\n", encoding="utf-8")
        config = AshConfig(honor_ignore_files=False)
        trusted = AshConfig(honor_ignore_files=True)
        with caplog.at_level(logging.WARNING):
            confine_honor_ignore_files(
                config,
                trusted,
                None,
                [base],
                documents={base.resolve(): {"honor_ignore_files": False}},
                chain=[base],
                environment_paths={base},
            )
        assert config.honor_ignore_files is True
        assert "<value>" in caplog.text, caplog.text
        assert "qzbase-7731" not in caplog.text, caplog.text


class TestOperatorConfigDigest:
    def test_each_file_is_read_through_the_bounded_reader(self, tmp_path, monkeypatch):
        operator = _write(tmp_path / "op" / "ash.yaml", "project_name: op\n")
        from automated_security_helper.config import config_sources

        # The chain as resolved, and the bounded reader answering other bytes
        # than the file holds: the digest is of what the reader gives.
        monkeypatch.setattr(
            module,
            "resolve_config_document",
            lambda *a, **k: SimpleNamespace(chain=[operator]),
        )
        monkeypatch.setattr(
            config_sources, "read_config_bytes", lambda path, expect=None: b"qz-bytes"
        )
        expected = hashlib.sha256()
        expected.update(f"{operator.as_posix()}\0{len(b'qz-bytes')}\0".encode("utf-8"))
        expected.update(b"qz-bytes")
        assert operator_config_digest(operator) == expected.hexdigest()


class TestOverlayRefusal:
    def test_an_environment_chosen_base_is_named_value(self, tmp_path, monkeypatch):
        base = tmp_path / "repo" / "qzbase-5519.yaml"
        root = tmp_path / "op" / "ash.yaml"
        overlay = SimpleNamespace(
            chain=[base, root], names={}, environment_paths=frozenset({base})
        )
        monkeypatch.setattr(module, "scanned_trees", lambda path: [tmp_path / "repo"])
        monkeypatch.setattr(
            module, "_not_the_operators", lambda chain, trees, names: [base]
        )
        monkeypatch.setattr(
            module,
            "_whose_file",
            lambda path, trees, names: (
                "is inside the scanned tree",
                "the scanned tree",
            ),
        )
        monkeypatch.setattr(module, "tree_holding", lambda path, trees, names: None)
        with pytest.raises(ASHConfigValidationError) as refused:
            module._refuse_unless_the_operators(overlay, tmp_path / "repo")
        text = str(refused.value)
        assert "<value>" in text, text
        assert "qzbase-5519" not in text, text


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX directory modes")
@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0, reason="root searches any directory"
)
def test_an_overlay_under_an_unsearchable_directory_is_refused_not_raised(tmp_path):
    folder = tmp_path / "closed"
    folder.mkdir()
    overlay = folder / "ash.yaml"
    overlay.write_text("project_name: p\n", encoding="utf-8")
    folder.chmod(0o000)
    try:
        with pytest.raises(ASHConfigSourceError):
            _load_overlay(overlay, None, None, lambda path: False)
    finally:
        folder.chmod(0o755)


def test_the_operator_scanner_view_holds_anchored_tool_paths(tmp_path):
    operator = _write(tmp_path / "op" / "ash.yaml", "project_name: op\n")
    reads = {
        operator.resolve(): {
            "project_name": "op",
            "scanners": {"bandit": {"options": {"config_file": "rel.yaml"}}},
        }
    }
    view = module._with_operator_chain_scanners(
        AshConfig(), [operator], [], reads, frozenset()
    )
    assert view is not None
    # The view answers for the singular plugin type the ownership check asks
    # with (operator_wrote_value); any other type is None by design.
    section = view.get_plugin_config("scanner", "bandit")
    value = section["options"]["config_file"]
    assert value != "rel.yaml", value
    assert Path(value).resolve() == (operator.parent / "rel.yaml").resolve()


def test_the_confined_sandbox_settings_name_every_replaced_list():
    settings = {setting for _, setting in _CONFINED_SANDBOX_SETTINGS}
    assert {
        "network_scanners",
        "extra_read_paths",
        "read_path_scanners",
        "env_scanners",
    } <= settings


def test_operator_paths_takes_the_carried_default_config(tmp_path, monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("the ASH_CONFIG chain was resolved a second time")

    monkeypatch.setattr(module, "get_default_config", refuse)
    record = _operator_paths(
        [],
        [],
        [],
        tmp_path,
        None,
        untrusted=False,
        overrides=[],
        default_config=AshConfig(project_name="qzcarried"),
    )
    assert record.documents and record.documents[0]["project_name"] == "qzcarried"
