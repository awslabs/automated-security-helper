# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""config_validator's record of what a file read from the environment, and the
structural warnings of a check, on the shapes that lost a value or aborted.

- A mapping key written as a reference that resolves onto another key of its
  mapping merges the two entries; pairing the referenced keys with the leftover
  resolved keys by position left the merged value neither redacted nor
  recorded, and misaligned every later referenced key.
- The part of a value the variable gave is read up to the text that follows the
  reference as written; stripping that text first folded the blank between
  them into the part.
- A patch pointer's segment of digits is typed as an index before the record
  says whether a mapping or a list holds it; a mapping keyed by the digits as
  text then found no place for the rewrite.
- One ignore or suppression path whose stat raises aborted every structural
  warning of ``check_config_file``.
- A '-'/'_' respelling of a declared top-level field was said to be ignored,
  while an extends merge folds it onto the declared spelling and applies it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.config.ash_config import (
    AshConfig,
    resolve_env_references,
)
from automated_security_helper.config.config_validator import (
    ConfigValidator,
    _environment_part,
    _interpolated_pairs,
    _quietly_resolved,
    _written_rewrites,
    environment_record_read,
    path_pattern_advice,
    recorded_value_at,
)
from automated_security_helper.core.exceptions import ASHConfigUnsetVariableError

pytestmark = pytest.mark.unit

#: Names a config file may read: the ASH_ prefix, and no credential suffix
#: (``_KEY``, ``_TOKEN``, ... are refused by ``config_env_var_is_secret_shaped``
#: and left as written, which would pair nothing here).
KEY_VARIABLE = "ASH_PAIRING_NAME"
VALUE_VARIABLE = "ASH_PAIRING_VALUE"
OTHER_KEY_VARIABLE = "ASH_PAIRING_OTHER_NAME"
OTHER_VALUE_VARIABLE = "ASH_PAIRING_OTHER_VALUE"
#: Long enough to be redacted wherever it appears, and unlike any other text.
MERGED_VALUE = "qzmerged-secret-5519"
PART_VARIABLE = "ASH_PART_CANARY"
PART_VALUE = "qzpart-value-7731"


class TestReferencedKeyPairing:
    """A key written as ``${VAR}`` pairs with the key it resolves to."""

    @pytest.fixture(autouse=True)
    def _variables(self, monkeypatch):
        monkeypatch.setenv(KEY_VARIABLE, "a")
        monkeypatch.setenv(VALUE_VARIABLE, MERGED_VALUE)

    @staticmethod
    def _readings():
        """The two readings of one mapping: written, the key ``a`` and a key
        read from the environment that also resolves to ``a``; resolved, the
        one entry the loader keeps, the later one's value."""
        written = {"a": "1", f"${{{KEY_VARIABLE}}}": f"${{{VALUE_VARIABLE}}}"}
        resolved = {"a": MERGED_VALUE}
        return written, resolved

    def test_the_merged_entrys_value_is_paired(self):
        written, resolved = self._readings()

        pairs = _interpolated_pairs(written, resolved)

        assert (MERGED_VALUE, f"${{{VALUE_VARIABLE}}}") in pairs, pairs
        assert ("a", f"${{{KEY_VARIABLE}}}") in pairs, pairs

    def test_the_merged_entry_gets_a_value_and_a_key_rewrite(self):
        written, resolved = self._readings()

        rewrites = _written_rewrites(written, resolved)

        shapes = {(rewrite.kind, tuple(rewrite.path)) for rewrite in rewrites}
        assert ("value", ("a",)) in shapes, rewrites
        assert ("key", ()) in shapes, rewrites
        (value,) = [rewrite for rewrite in rewrites if rewrite.kind == "value"]
        assert value.resolved == MERGED_VALUE
        assert f"${{{VALUE_VARIABLE}}}" in value.written

    def test_a_later_referenced_key_does_not_shift_the_pairing(self, monkeypatch):
        """Two referenced keys, the first merging onto a plain key: the second
        still pairs with its own resolved key, not with the leftover one."""
        monkeypatch.setenv(OTHER_KEY_VARIABLE, "b")
        monkeypatch.setenv(OTHER_VALUE_VARIABLE, "qzother-secret-6624")
        written = {
            "a": "1",
            f"${{{KEY_VARIABLE}}}": f"${{{VALUE_VARIABLE}}}",
            f"${{{OTHER_KEY_VARIABLE}}}": f"${{{OTHER_VALUE_VARIABLE}}}",
        }
        resolved = {"a": MERGED_VALUE, "b": "qzother-secret-6624"}

        pairs = _interpolated_pairs(written, resolved)

        assert ("qzother-secret-6624", f"${{{OTHER_VALUE_VARIABLE}}}") in pairs, pairs
        assert ("b", f"${{{OTHER_KEY_VARIABLE}}}") in pairs, pairs
        assert (MERGED_VALUE, f"${{{VALUE_VARIABLE}}}") in pairs, pairs

    def test_a_plain_key_written_last_keeps_its_own_value(self):
        """The loader keeps the last entry written under a name, so a plain key
        after the referenced one holds the value: the referenced entry's value
        is not paired with it."""
        written = {f"${{{KEY_VARIABLE}}}": f"${{{VALUE_VARIABLE}}}", "a": "1"}
        resolved = {"a": "1"}

        pairs = _interpolated_pairs(written, resolved)

        assert ("a", f"${{{KEY_VARIABLE}}}") in pairs, pairs
        assert not [pair for pair in pairs if pair[0] == "1"], pairs

    def test_a_plain_key_written_last_gets_no_key_rewrite(self):
        """The overwritten referenced entry's key must not rename the plain
        entry that survived it."""
        written = {f"${{{KEY_VARIABLE}}}": f"${{{VALUE_VARIABLE}}}", "a": "1"}
        resolved = {"a": "1"}

        rewrites = _written_rewrites(written, resolved)

        assert [rewrite for rewrite in rewrites if rewrite.kind == "key"] == [], (
            rewrites
        )

    def test_a_key_the_loader_kept_literal_pairs_with_itself(self):
        """A JSON or TOML file resolves no key, and a quoted YAML key is not
        read by the implicit resolver, so the loader keeps the key as written;
        the value under it is still paired."""
        written = {f"${{{KEY_VARIABLE}}}": f"${{{VALUE_VARIABLE}}}"}
        resolved = {f"${{{KEY_VARIABLE}}}": MERGED_VALUE}

        pairs = _interpolated_pairs(written, resolved)

        assert (MERGED_VALUE, f"${{{VALUE_VARIABLE}}}") in pairs, pairs
        assert not [pair for pair in pairs if pair[0] == f"${{{KEY_VARIABLE}}}"], pairs

    def test_a_key_that_resolves_to_no_key_pairs_by_position(self, monkeypatch):
        """A referenced key whose resolved key cannot be told still pairs, in
        order, with the resolved key no other entry claims, as every referenced
        key once did, so the value under it is redacted and recorded."""
        monkeypatch.delenv("ASH_PAIRING_UNSET", raising=False)
        written = {"a": "1", "${ASH_PAIRING_UNSET}": f"${{{VALUE_VARIABLE}}}"}
        resolved = {"a": "1", "b": MERGED_VALUE}

        pairs = _interpolated_pairs(written, resolved)

        assert (MERGED_VALUE, f"${{{VALUE_VARIABLE}}}") in pairs, pairs

    def test_a_plugin_section_key_the_fold_respelled_is_paired(self, monkeypatch):
        """environment_record_read folds the resolved mapping's plugin sections
        onto their canonical spelling, so the key a reference resolved to can
        differ from the section's key by '-' for '_'."""
        monkeypatch.setenv(KEY_VARIABLE, "cloudwatch_logs")
        written = {
            "reporters": {f"${{{KEY_VARIABLE}}}": {"token": f"${{{VALUE_VARIABLE}}}"}}
        }
        resolved = {"reporters": {"cloudwatch-logs": {"token": MERGED_VALUE}}}

        pairs = _interpolated_pairs(written, resolved)

        assert (MERGED_VALUE, f"${{{VALUE_VARIABLE}}}") in pairs, pairs


class TestQuietKeyResolution:
    """Building the record resolves a referenced key by the loader's rule
    without logging the load's warnings again or reading what it did not."""

    @pytest.mark.parametrize(
        "written_key",
        ["${HOME}", "${ASH_PAIRING_KEY}", "${ASH_PAIRING_UNSET:dflt}"],
    )
    def test_pairing_logs_no_env_warning(self, caplog, monkeypatch, written_key):
        monkeypatch.delenv("ASH_PAIRING_UNSET", raising=False)
        monkeypatch.setenv("ASH_PAIRING_KEY", "a")
        written = {written_key: "x"}
        resolved = {"${HOME}": "x", "${ASH_PAIRING_KEY}": "x", "dflt": "x"}

        with caplog.at_level("WARNING", logger="ash"):
            _interpolated_pairs(written, resolved)
            _written_rewrites(written, resolved)

        assert caplog.records == [], [record.getMessage() for record in caplog.records]

    @pytest.mark.parametrize(
        "text",
        [
            "plain",
            "${ASH_PAIRING_NAME}",
            "${ASH_PAIRING_NAME} tail",
            "${ASH_PAIRING_UNSET:dflt}",
            "${ASH_PAIRING_UNSET:None}",
            "${ASH_PAIRING_UNSET:-dflt}",
            "${ASH_PAIRING_KEY}",
            "${HOME}",
            "${ASH_PAIRING_NAME}x}",
            "${ASH_PAIRING_NAME}/${ASH_PAIRING_KEY}",
            "${ASH_PAIRING_NAME:x}/${ASH_PAIRING_KEY}",
            "${ASH_PAIRING_UNSET:x}${ASH_PAIRING_KEY}",
            "${ASH_PAIRING_NAME:{}}",
            "${ASH_PAIRING_UNSET:{}}",
            "${ASH_PAIRING_UNSET:\\d{3}}",
            "${ASH_PAIRING_UNSET:{a}",
            "${ASH_PAIRING_NAME:a\nb}",
            "${ASH_PAIRING_NAME-x}",
            "${ASH_PAIRING_BLANK}",
            "${ASH_PAIRING_BLANK} tail",
            "${ASH_PAIRING_UNSET:}",
            "${ASH_PAIRING_UNSET:dflt} tail",
            "${ASH_PAIRING_UNSET:None} tail",
        ],
    )
    def test_the_quiet_resolution_agrees_with_the_loader(self, monkeypatch, text):
        monkeypatch.setenv("ASH_PAIRING_NAME", "a")
        monkeypatch.setenv("ASH_PAIRING_KEY", "a")
        monkeypatch.setenv("ASH_PAIRING_BLANK", "")
        monkeypatch.delenv("ASH_PAIRING_UNSET", raising=False)

        assert _quietly_resolved(text) == resolve_env_references(text)

    def test_an_unset_variable_with_no_default_is_none_where_the_loader_raises(
        self, monkeypatch
    ):
        monkeypatch.delenv("ASH_PAIRING_UNSET", raising=False)

        with pytest.raises(ASHConfigUnsetVariableError):
            resolve_env_references("${ASH_PAIRING_UNSET}")
        assert _quietly_resolved("${ASH_PAIRING_UNSET}") is None


def test_the_environment_part_drops_a_tails_trailing_blank():
    """A quoted ``"${VAR} tail "`` is stripped by the loader, so the tail as
    written is never a suffix of the value; matched without its trailing
    blanks, the part is the value, not the value plus a blank."""
    assert _environment_part("val tail", " tail ") == "val"
    assert _environment_part("val tail", " tail") == "val"
    assert _environment_part("val", "") == "val"


def test_the_environment_part_keeps_no_blank_from_the_rest(tmp_path, monkeypatch):
    """``!ENV ${VAR} tail``: the part the variable gave is the value, not the
    value plus the blank before ``tail``."""
    monkeypatch.setenv(PART_VARIABLE, PART_VALUE)
    path = tmp_path / ".ash.yaml"
    path.write_text(
        "global_settings:\n"
        "  ignore_paths:\n"
        "    - path: vendor/**\n"
        f"      reason: !ENV ${{{PART_VARIABLE}}} tail\n",
        encoding="utf-8",
    )

    values, rewrites = environment_record_read([path], {}, {})

    (rewrite,) = rewrites
    assert rewrite.resolved == f"{PART_VALUE} tail"
    assert rewrite.environment_part == PART_VALUE
    assert rewrite.reference == f"${{{PART_VARIABLE}}}"
    assert PART_VALUE in values


def test_a_rewrite_into_a_mapping_keyed_by_digits_finds_its_place():
    """A pointer segment typed as the index 123 names the key "123" of a
    mapping that spells it as text."""
    document = {"a": {"123": "v"}}

    assert recorded_value_at(document, document, ("a", 123)) == "v"
    assert recorded_value_at(document, document, ("a", "123")) == "v"


def test_a_rewrite_under_a_bases_plugin_spelling_finds_the_merged_section():
    """The extends merge joins ``zzcustom`` and ``ZzCustomReporter`` under the
    child's spelling; a base's rewrite path keeps the base's spelling and still
    finds the merged section, read under the reporters segment's own model as
    the record is."""
    config = AshConfig.model_validate(
        {
            "project_name": "demo",
            "reporters": {"ZzCustomReporter": {"options": {"bucket": "v"}}},
        }
    )
    dumped = config.model_dump(mode="json", by_alias=True)

    assert (
        recorded_value_at(
            config, dumped, ("reporters", "zzcustom", "options", "bucket")
        )
        == "v"
    )


def test_a_plain_mapping_key_is_not_matched_as_a_plugin_name():
    """The plugin-name lookup mirrors the merge, which joins plugin spellings
    directly under the scanners, reporters and converters segments only: a
    tag mapping's ``Owner`` is not another spelling of a path's ``owner``, so
    the rewrite finds no place there instead of another entry's."""
    config = AshConfig.model_validate(
        {
            "project_name": "demo",
            "reporters": {"ZzCustomReporter": {"options": {"tags": {"Owner": "v"}}}},
        }
    )
    dumped = config.model_dump(mode="json", by_alias=True)
    path = ("reporters", "ZzCustomReporter", "options", "tags", "owner")

    assert recorded_value_at(config, dumped, path) is None


def test_path_pattern_advice_survives_a_stat_that_raises(tmp_path, monkeypatch):
    """A pattern whose stat raises (a parent that cannot be searched, a name
    past the system's length) is advised on as "fine", not raised through
    every other structural warning."""

    is_dir = Path.is_dir

    def refused(self):
        # Only the paths the advice stats; a fixture's teardown stats its own
        # directories while this patch is still in place.
        if self == tmp_path or tmp_path in self.parents:
            raise PermissionError(13, "Permission denied", str(self))
        return is_dir(self)

    monkeypatch.setattr(Path, "is_dir", refused)

    assert path_pattern_advice("some/dir", tmp_path, ignore_path=True) is None
    assert path_pattern_advice("./some/dir", tmp_path, ignore_path=True) is not None


def test_a_case_only_match_survives_a_stat_that_raises(tmp_path, monkeypatch):
    """A directory that can be listed but whose entries cannot be stat'ed: the
    case-only spelling is still advised, without its trailing slash, and the
    check does not abort."""
    (tmp_path / "Some").mkdir()
    is_dir = Path.is_dir

    def refused(self):
        if self == tmp_path or tmp_path in self.parents:
            raise PermissionError(13, "Permission denied", str(self))
        return is_dir(self)

    monkeypatch.setattr(Path, "is_dir", refused)

    advice = path_pattern_advice("some", tmp_path, ignore_path=True)

    assert advice is not None and "Some" in advice, advice


def test_a_respelled_top_level_field_alone_is_unknown_with_the_fix_named(tmp_path):
    """A file read on its own does not read 'fail-on-findings' as the declared
    field, so the warning keeps the unknown-field prefix `ash config lint`
    files it under and names the spelling that is read."""
    cfg = tmp_path / ".ash.yaml"
    cfg.write_text("project_name: demo\nfail-on-findings: true\n", encoding="utf-8")

    check = ConfigValidator.check_config_file(cfg)

    unknown = [
        w for w in check.warnings if w.startswith("Unknown top-level field 'fail-on-")
    ]
    assert unknown, check.warnings
    assert "write 'fail_on_findings'" in unknown[0], unknown
    assert "folds it onto" not in unknown[0], unknown


def test_a_respelled_top_level_field_a_chain_applies_is_named_as_folded(tmp_path):
    """A child whose base sets the declared spelling: the extends merge folds
    the child's respelled key onto it and applies the child's value."""
    base = tmp_path / "base.yaml"
    base.write_text("project_name: demo\nfail_on_findings: false\n", encoding="utf-8")
    child = tmp_path / ".ash.yaml"
    child.write_text("extends: base.yaml\nfail-on-findings: true\n", encoding="utf-8")

    check = ConfigValidator.check_config_file(child)

    folded = [
        w for w in check.warnings if w.startswith("Unknown top-level field 'fail-on-")
    ]
    assert folded, check.warnings
    assert "folds it onto 'fail_on_findings' and applies its value" in folded[0], folded


def test_a_respelled_mapping_field_a_chain_merges_is_named_as_folded(tmp_path):
    """A mapping-valued field: the merge joins the child's mapping into the
    base's, so the merged value holds the base's keys too and never equals the
    child's; the check reads containment, as the merge folds, not equality."""
    base = tmp_path / "base.yaml"
    base.write_text(
        "project_name: demo\nglobal_settings:\n  severity_threshold: LOW\n",
        encoding="utf-8",
    )
    child = tmp_path / ".ash.yaml"
    child.write_text(
        "extends: base.yaml\nglobal-settings:\n  ignore_paths: []\n", encoding="utf-8"
    )

    check = ConfigValidator.check_config_file(child)

    folded = [
        w for w in check.warnings if w.startswith("Unknown top-level field 'global-")
    ]
    assert folded, check.warnings
    assert "folds it onto 'global_settings' and applies its value" in folded[0], folded


def test_an_empty_respelled_mapping_field_is_not_named_as_applied(tmp_path):
    """``global-settings: {}`` sets nothing, so the chain applies none of its
    value; the warning says to write the declared spelling, as for a file
    alone, not that the chain folds and applies it."""
    base = tmp_path / "base.yaml"
    base.write_text(
        "project_name: demo\nglobal_settings:\n  severity_threshold: LOW\n",
        encoding="utf-8",
    )
    child = tmp_path / ".ash.yaml"
    child.write_text("extends: base.yaml\nglobal-settings: {}\n", encoding="utf-8")

    check = ConfigValidator.check_config_file(child)

    respelled = [
        w for w in check.warnings if w.startswith("Unknown top-level field 'global-")
    ]
    assert respelled, check.warnings
    assert "folds it onto" not in respelled[0], respelled
    assert "write 'global_settings'" in respelled[0], respelled


def test_a_respelled_mapping_with_an_empty_nested_mapping_is_named_as_folded(
    tmp_path,
):
    """``mcp: {}`` nested under a respelled ``global-settings`` the chain does
    fold: the merge applies ``severity_threshold: HIGH`` and places the empty
    mapping where the file wrote it, so the whole value is folded and applied.
    Reading the empty-mapping rule at every level said the value was ignored."""
    base = tmp_path / "base.yaml"
    base.write_text(
        "project_name: demo\nglobal_settings:\n  severity_threshold: LOW\n",
        encoding="utf-8",
    )
    child = tmp_path / ".ash.yaml"
    child.write_text(
        "extends: base.yaml\nglobal-settings:\n  severity_threshold: HIGH\n  mcp: {}\n",
        encoding="utf-8",
    )

    check = ConfigValidator.check_config_file(child)

    folded = [
        w for w in check.warnings if w.startswith("Unknown top-level field 'global-")
    ]
    assert folded, check.warnings
    assert "folds it onto 'global_settings' and applies its value" in folded[0], folded


def test_an_unknown_top_level_field_is_still_unknown(tmp_path):
    cfg = tmp_path / ".ash.yaml"
    cfg.write_text("project_name: demo\nfoo_unknown: 1\n", encoding="utf-8")

    check = ConfigValidator.check_config_file(cfg)

    assert any(
        w == "Unknown top-level field 'foo_unknown' - a scan ignores it"
        for w in check.warnings
    ), check.warnings
