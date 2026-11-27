# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The retired-scanner alias layer: one table, one lookup, one comparison key.

``SCANNER_NAME_ALIASES`` is empty today -- no shipped scanner is retired -- so
every live behavior is unchanged: ``canonical_scanner_name`` answers the name
it was given and ``selection_key`` is strip-then-lower. These tests pin the
mechanism itself by patching one alias row in, so the day a retirement adds a
real row, the row is the whole change: the config fold, the scan phase's
resolution and the dependencies tool lookup are already wired through the
table. Adapted from the v4 program (#981), whose table carried a live row.
"""

import copy
import logging

import pytest
import yaml

from automated_security_helper.utils import scanner_names
from automated_security_helper.utils.scanner_names import (
    SCANNER_NAME_ALIASES,
    canonical_scanner_name,
    selection_key,
)

pytestmark = pytest.mark.unit


def test_the_table_is_empty_until_a_scanner_is_retired():
    assert SCANNER_NAME_ALIASES == {}


@pytest.mark.parametrize(
    "typed, key",
    [
        ("Bandit", "bandit"),
        (" bandit ", "bandit"),
        ("OpenGrep", "opengrep"),
        ("cfn-nag", "cfn-nag"),
    ],
)
def test_the_key_strips_and_lowers_with_an_empty_table(typed, key):
    assert selection_key(typed) == key


@pytest.fixture
def retired_oldname(monkeypatch):
    """One synthetic retirement: ``oldname`` is served by the bandit plugin."""
    monkeypatch.setitem(scanner_names.SCANNER_NAME_ALIASES, "oldname", "bandit")
    return "oldname"


@pytest.mark.parametrize("spelling", ["oldname", "Old-Name", " old_name ", "OLDNAME"])
def test_a_retired_name_resolves_in_any_spelling(retired_oldname, spelling):
    assert canonical_scanner_name(spelling.strip()) == "bandit"
    assert selection_key(spelling) == "bandit"


def test_an_unretired_name_answers_itself_in_the_callers_spelling(retired_oldname):
    assert canonical_scanner_name("Checkov") == "Checkov"


def test_a_retired_name_and_its_replacement_share_a_key(retired_oldname):
    assert selection_key("Old-Name") == selection_key("bandit")


def test_the_scan_phase_resolves_and_logs_the_mapping(retired_oldname, caplog):
    from automated_security_helper.core.phases.scan_phase import (
        _resolve_scanner_name_aliases,
    )

    with caplog.at_level(logging.INFO, logger="ash"):
        resolved = _resolve_scanner_name_aliases(["oldname", "checkov"])
    assert resolved == ["bandit", "checkov"]
    assert any(
        "oldname is an alias of the bandit plugin" in record.getMessage()
        for record in caplog.records
    )


def test_the_dependencies_tool_lookup_resolves_a_retired_name(retired_oldname):
    from automated_security_helper.cli.dependencies import _resolve_tool_aliases

    assert _resolve_tool_aliases(["Oldname"])["Oldname"] == "bandit"


def test_the_dependencies_tool_lookup_still_passes_unknown_names_through():
    from automated_security_helper.cli.dependencies import _resolve_tool_aliases

    assert _resolve_tool_aliases(["no-such-tool"])["no-such-tool"] == "no-such-tool"


def test_the_config_fold_applies_a_retired_section_to_the_serving_plugin(
    retired_oldname, caplog
):
    from automated_security_helper.config.ash_config import ScannerConfigSegment

    with caplog.at_level(logging.INFO, logger="ash"):
        segment = ScannerConfigSegment.model_validate(
            {"oldname": {"name": "oldname", "enabled": False}}
        )
    assert segment.bandit.enabled is False
    # The alias section never lands in the extra="allow" bucket as an unknown
    # third-party scanner, and its name literal does not reach the fold target.
    assert "oldname" not in (segment.__pydantic_extra__ or {})
    assert str(segment.bandit.name) == "bandit"
    assert any(
        "scanners.oldname is an alias of the bandit plugin" in record.getMessage()
        for record in caplog.records
    )


def test_the_fold_drops_options_the_serving_plugin_does_not_declare(
    retired_oldname, caplog
):
    from automated_security_helper.config.ash_config import ScannerConfigSegment

    with caplog.at_level(logging.WARNING, logger="ash"):
        segment = ScannerConfigSegment.model_validate(
            {"oldname": {"enabled": True, "options": {"retired_only_knob": 5}}}
        )
    assert segment.bandit.enabled is True
    assert not hasattr(segment.bandit.options, "retired_only_knob")
    assert any(
        "retired_only_knob" in record.getMessage() and "dropped" in record.getMessage()
        for record in caplog.records
    )


def test_the_operators_alias_section_wins_over_the_canonical_defaults(retired_oldname):
    from automated_security_helper.config.ash_config import ScannerConfigSegment

    segment = ScannerConfigSegment.model_validate(
        {"bandit": {"enabled": True}, "oldname": {"enabled": False}}
    )
    assert segment.bandit.enabled is False


def test_without_a_table_row_the_fold_changes_nothing():
    from automated_security_helper.config.ash_config import ScannerConfigSegment

    segment = ScannerConfigSegment.model_validate({"bandit": {"enabled": False}})
    assert segment.bandit.enabled is False


# Across files the extending file wins, whichever spelling either one uses.
# Inside one file the retired spelling is the overlay (the tests above); a
# file's own ``patch`` is read against the file as it wrote it.


def _write(path, document):
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return path


def _load(monkeypatch, path):
    """The configuration a file and its ``extends`` chain make, as a scan loads it."""
    from automated_security_helper.config.ash_config import AshConfig

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    return AshConfig.from_file(path)


def test_a_bases_retired_section_does_not_beat_the_childs_canonical_one(
    retired_oldname, tmp_path, monkeypatch
):
    _write(tmp_path / "base.yaml", {"scanners": {"oldname": {"enabled": False}}})
    child = _write(
        tmp_path / "child.yaml",
        {"extends": "base.yaml", "scanners": {"bandit": {"enabled": True}}},
    )

    assert _load(monkeypatch, child).scanners.bandit.enabled is True


def test_a_bases_retired_options_reach_the_serving_plugin_under_the_childs_enabled(
    retired_oldname, tmp_path, monkeypatch
):
    _write(
        tmp_path / "base.yaml",
        {
            "scanners": {
                "oldname": {"enabled": False, "options": {"confidence_level": "high"}}
            }
        },
    )
    child = _write(
        tmp_path / "child.yaml",
        {"extends": "base.yaml", "scanners": {"bandit": {"enabled": True}}},
    )

    config = _load(monkeypatch, child)

    assert config.scanners.bandit.enabled is True
    assert config.scanners.bandit.options.confidence_level == "high"


def test_the_later_base_wins_over_an_earlier_one_that_uses_the_retired_name(
    retired_oldname, tmp_path, monkeypatch
):
    _write(tmp_path / "b1.yaml", {"scanners": {"oldname": {"enabled": False}}})
    _write(tmp_path / "b2.yaml", {"scanners": {"bandit": {"enabled": True}}})
    child = _write(tmp_path / "child.yaml", {"extends": ["b1.yaml", "b2.yaml"]})

    assert _load(monkeypatch, child).scanners.bandit.enabled is True


def test_the_later_base_wins_over_an_earlier_one_when_it_uses_the_retired_name(
    retired_oldname, tmp_path, monkeypatch
):
    _write(tmp_path / "b1.yaml", {"scanners": {"bandit": {"enabled": False}}})
    _write(tmp_path / "b2.yaml", {"scanners": {"oldname": {"enabled": True}}})
    child = _write(tmp_path / "child.yaml", {"extends": ["b1.yaml", "b2.yaml"]})

    assert _load(monkeypatch, child).scanners.bandit.enabled is True


def test_a_childs_retired_section_beats_the_bases_canonical_one(
    retired_oldname, tmp_path, monkeypatch
):
    _write(tmp_path / "base.yaml", {"scanners": {"bandit": {"enabled": False}}})
    child = _write(
        tmp_path / "child.yaml",
        {"extends": "base.yaml", "scanners": {"oldname": {"enabled": True}}},
    )

    assert _load(monkeypatch, child).scanners.bandit.enabled is True


def test_a_file_with_only_the_canonical_section_is_read_as_written(
    retired_oldname, tmp_path, monkeypatch
):
    child = _write(tmp_path / "child.yaml", {"scanners": {"bandit": {"enabled": True}}})

    assert _load(monkeypatch, child).scanners.bandit.enabled is True


def test_a_file_with_only_the_retired_section_still_applies_it(
    retired_oldname, tmp_path, monkeypatch
):
    base = _write(tmp_path / "base.yaml", {"scanners": {"oldname": {"enabled": False}}})

    assert _load(monkeypatch, base).scanners.bandit.enabled is False


def test_a_files_own_patch_still_names_the_retired_section_it_wrote(
    retired_oldname, tmp_path, monkeypatch
):
    """The extending file is not folded before its own ``patch`` runs."""
    path = _write(
        tmp_path / "one.yaml",
        {
            "scanners": {"oldname": {"enabled": True}},
            "patch": [
                {"op": "replace", "path": "/scanners/oldname/enabled", "value": False}
            ],
        },
    )

    assert _load(monkeypatch, path).scanners.bandit.enabled is False


def test_one_file_holding_both_spellings_reads_the_retired_one_last(
    retired_oldname, tmp_path, monkeypatch
):
    path = _write(
        tmp_path / "one.yaml",
        {"scanners": {"bandit": {"enabled": True}, "oldname": {"enabled": False}}},
    )

    assert _load(monkeypatch, path).scanners.bandit.enabled is False


def test_a_file_holding_both_spellings_keeps_that_rule_as_a_base(
    retired_oldname, tmp_path, monkeypatch
):
    _write(
        tmp_path / "base.yaml",
        {"scanners": {"bandit": {"enabled": True}, "oldname": {"enabled": False}}},
    )
    child = _write(tmp_path / "child.yaml", {"extends": "base.yaml"})

    assert _load(monkeypatch, child).scanners.bandit.enabled is False


# The fold the loader runs on each document, on its own.


def test_the_fold_answers_its_input_when_no_key_is_retired(retired_oldname):
    from automated_security_helper.config.ash_config import fold_scanner_name_aliases

    scanners = {"bandit": {"enabled": True}}

    assert fold_scanner_name_aliases(scanners) is scanners
    assert fold_scanner_name_aliases("not a mapping") == "not a mapping"


def test_the_fold_reads_the_declared_options_from_the_segment_class_it_is_given(
    retired_oldname,
):
    from pydantic import BaseModel

    from automated_security_helper.config.ash_config import fold_scanner_name_aliases

    class _DeclaresNothing(BaseModel):
        pass

    scanners = {"oldname": {"options": {"retired_only_knob": 5}}}

    # A class with no bandit field leaves the options as written; the default
    # is the shipped segment, which declares them and drops the knob.
    kept = fold_scanner_name_aliases(scanners, _DeclaresNothing)
    dropped = fold_scanner_name_aliases(scanners)

    assert kept["bandit"]["options"] == {"retired_only_knob": 5}
    assert "retired_only_knob" not in dropped["bandit"].get("options", {})


def test_the_document_fold_answers_the_same_object_when_nothing_folds(retired_oldname):
    from automated_security_helper.config.ash_config import (
        fold_document_scanner_aliases,
    )

    document = {"project_name": "p", "scanners": {"bandit": {"enabled": True}}}

    assert fold_document_scanner_aliases(document) is document


@pytest.mark.parametrize(
    "document",
    [None, [], "scanners", {}, {"scanners": None}, {"scanners": ["oldname"]}],
)
def test_the_document_fold_passes_a_document_with_no_scanners_mapping_through(
    retired_oldname, document
):
    from automated_security_helper.config.ash_config import (
        fold_document_scanner_aliases,
    )

    assert fold_document_scanner_aliases(document) is document


def test_the_document_fold_copies_what_it_changes_and_leaves_its_input_alone(
    retired_oldname,
):
    from automated_security_helper.config.ash_config import (
        fold_document_scanner_aliases,
    )

    document = {
        "project_name": "p",
        "scanners": {
            "bandit": {"enabled": True},
            "oldname": {"enabled": False, "options": {"retired_only_knob": 5}},
        },
    }
    before = copy.deepcopy(document)

    folded = fold_document_scanner_aliases(document)

    assert document == before
    assert folded is not document
    assert folded["project_name"] == "p"
    assert "oldname" not in folded["scanners"]
    assert folded["scanners"]["bandit"]["enabled"] is False
    assert "retired_only_knob" not in folded["scanners"]["bandit"].get("options", {})


def test_the_document_fold_logs_only_when_asked_to(retired_oldname, caplog):
    from automated_security_helper.config.ash_config import (
        fold_document_scanner_aliases,
    )

    document = {
        "scanners": {"oldname": {"enabled": False, "options": {"retired_only_knob": 5}}}
    }

    def about_the_retired_name():
        return [r for r in caplog.records if "oldname" in r.getMessage()]

    with caplog.at_level(logging.INFO, logger="ash"):
        fold_document_scanner_aliases(document)
    assert about_the_retired_name()  # the control: the same call does log

    caplog.clear()
    with caplog.at_level(logging.INFO, logger="ash"):
        fold_document_scanner_aliases(document, log=False)
    assert about_the_retired_name() == []
