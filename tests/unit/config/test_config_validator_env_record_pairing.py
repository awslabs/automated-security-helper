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

from automated_security_helper.config.config_validator import (
    ConfigValidator,
    _interpolated_pairs,
    _written_rewrites,
    environment_record_read,
    path_pattern_advice,
    recorded_value_at,
)

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
    """The extends merge joins ``s3`` and ``S3Reporter`` under the child's
    spelling; a base's rewrite path keeps the base's spelling and still finds
    the merged section."""
    document = {"reporters": {"S3Reporter": {"options": {"bucket": "v"}}}}

    assert (
        recorded_value_at(document, document, ("reporters", "s3", "options", "bucket"))
        == "v"
    )


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


def test_a_respelled_top_level_field_is_named_as_folded(tmp_path):
    cfg = tmp_path / ".ash.yaml"
    cfg.write_text("project_name: demo\nfail-on-findings: true\n", encoding="utf-8")

    check = ConfigValidator.check_config_file(cfg)

    folded = [w for w in check.warnings if "folds it onto 'fail_on_findings'" in w]
    assert folded, check.warnings
    assert "'fail-on-findings'" in folded[0], folded
    unknown = [w for w in check.warnings if w.startswith("Unknown top-level field")]
    assert unknown == [], check.warnings


def test_an_unknown_top_level_field_is_still_unknown(tmp_path):
    cfg = tmp_path / ".ash.yaml"
    cfg.write_text("project_name: demo\nfoo_unknown: 1\n", encoding="utf-8")

    check = ConfigValidator.check_config_file(cfg)

    assert any(
        w == "Unknown top-level field 'foo_unknown' - a scan ignores it"
        for w in check.warnings
    ), check.warnings
