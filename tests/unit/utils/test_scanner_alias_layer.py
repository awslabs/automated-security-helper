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
def retired_oldname(plant_scanner_alias):
    """One synthetic retirement: ``oldname`` is served by the bandit plugin."""
    return plant_scanner_alias("oldname", "bandit")


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
# Inside one file the retired spelling is the overlay (the tests above). Each
# file's own sections are folded as the loader reads the file, before its
# ``patch`` applies, so a pointer in the retired spelling lands on the serving
# plugin's section.


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
    """The file's section is folded onto bandit's as the file is read, and its
    own ``patch``'s pointer in the retired spelling lands there."""
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


# A child's ``patch`` naming the retired section its BASE wrote. The base is
# folded before the child is layered over it, so the section is the serving
# plugin's by then, and the pointer lands there.


def _child_patching_its_base(tmp_path, base_scanners, *ops):
    _write(tmp_path / "base.yaml", {"scanners": base_scanners})
    return _write(tmp_path / "child.yaml", {"extends": "base.yaml", "patch": list(ops)})


def test_a_childs_replace_under_the_retired_name_reaches_its_bases_section(
    retired_oldname, tmp_path, monkeypatch
):
    child = _child_patching_its_base(
        tmp_path,
        {"oldname": {"enabled": True}},
        {"op": "replace", "path": "/scanners/oldname/enabled", "value": False},
    )

    assert _load(monkeypatch, child).scanners.bandit.enabled is False


def test_a_childs_remove_of_the_retired_name_removes_its_bases_section(
    retired_oldname, tmp_path, monkeypatch
):
    child = _child_patching_its_base(
        tmp_path,
        {"oldname": {"enabled": False, "options": {"confidence_level": "high"}}},
        {"op": "remove", "path": "/scanners/oldname"},
    )

    config = _load(monkeypatch, child)

    # The base's section is gone, so what it set is back to bandit's default.
    assert config.scanners.bandit.enabled is True
    assert config.scanners.bandit.options.confidence_level == "all"


def test_a_childs_add_of_the_whole_retired_section_replaces_its_bases(
    retired_oldname, tmp_path, monkeypatch
):
    child = _child_patching_its_base(
        tmp_path,
        {"oldname": {"enabled": False, "options": {"confidence_level": "high"}}},
        {
            "op": "add",
            "path": "/scanners/oldname",
            "value": {"options": {"confidence_level": "low"}},
        },
    )

    config = _load(monkeypatch, child)

    # An add of a whole object replaces the section: the child's setting
    # holds, and the base's other setting is back to its default instead of
    # surviving a key-by-key merge.
    assert config.scanners.bandit.options.confidence_level == "low"
    assert config.scanners.bandit.enabled is True


def test_a_childs_add_inside_the_retired_section_sets_the_option_on_bandit(
    retired_oldname, tmp_path, monkeypatch
):
    child = _child_patching_its_base(
        tmp_path,
        {"oldname": {"enabled": True, "options": {"confidence_level": "high"}}},
        {
            "op": "add",
            "path": "/scanners/oldname/options/ignore_nosec",
            "value": True,
        },
    )

    config = _load(monkeypatch, child)

    assert config.scanners.bandit.options.ignore_nosec is True
    # The add is inside the section, so the base's own option stays.
    assert config.scanners.bandit.options.confidence_level == "high"


def test_a_childs_test_op_under_the_retired_name_reads_its_bases_section(
    retired_oldname, tmp_path, monkeypatch
):
    """The guard's test and the write it guards aim at the one section."""
    child = _child_patching_its_base(
        tmp_path,
        {"oldname": {"enabled": True}},
        {"op": "test", "path": "/scanners/oldname/enabled", "value": True},
        {"op": "replace", "path": "/scanners/oldname/enabled", "value": False},
    )

    assert _load(monkeypatch, child).scanners.bandit.enabled is False


def test_a_childs_test_op_under_the_retired_name_compares_its_bases_value(
    retired_oldname, tmp_path, monkeypatch
):
    """The control for the test above: the op compares the base's value, so a
    value the base did not write is refused."""
    from automated_security_helper.core.exceptions import ASHConfigSourceError

    child = _child_patching_its_base(
        tmp_path,
        {"oldname": {"enabled": True}},
        {"op": "test", "path": "/scanners/oldname/enabled", "value": False},
    )

    with pytest.raises(ASHConfigSourceError) as refused:
        _load(monkeypatch, child)

    text = " ".join(str(refused.value).split())
    assert "'patch' entry 0 in" in text, text
    assert "does not equal the value the test op gives" in text, text


def test_a_pointer_at_a_name_neither_held_nor_retired_is_still_refused(
    retired_oldname, tmp_path, monkeypatch
):
    from automated_security_helper.core.exceptions import ASHConfigSourceError

    child = _child_patching_its_base(
        tmp_path,
        {"oldname": {"enabled": True}},
        {"op": "replace", "path": "/scanners/nosuchname/enabled", "value": False},
    )

    with pytest.raises(ASHConfigSourceError) as refused:
        _load(monkeypatch, child)

    text = " ".join(str(refused.value).split())
    assert "'patch' entry 0 in" in text, text
    assert "(replace at '/scanners/nosuchname/enabled') failed:" in text, text
    assert "the path does not fit the document it patches" in text, text


def test_a_childs_patch_of_the_canonical_section_its_base_wrote_still_lands(
    retired_oldname, tmp_path, monkeypatch
):
    child = _child_patching_its_base(
        tmp_path,
        {"bandit": {"enabled": True}},
        {"op": "replace", "path": "/scanners/bandit/enabled", "value": False},
    )

    assert _load(monkeypatch, child).scanners.bandit.enabled is False


# A child's ``patch`` in the retired spelling where no file of the chain wrote
# the section under the retired name: the base wrote bandit. The pointer then
# stays the retired name's own key, so a patch written while the name was a
# real scanner's never takes the serving plugin's section on the day the name
# is retired.


@pytest.mark.parametrize(
    "operation, refusal",
    [
        pytest.param(
            {"op": "remove", "path": "/scanners/oldname"},
            "the path does not fit the document it patches",
            id="remove",
        ),
        pytest.param(
            {"op": "replace", "path": "/scanners/oldname/enabled", "value": True},
            "the path does not fit the document it patches",
            id="replace",
        ),
        pytest.param(
            {"op": "test", "path": "/scanners/oldname/enabled", "value": False},
            "does not equal the value the test op gives",
            id="test",
        ),
    ],
)
def test_a_childs_op_under_the_retired_name_leaves_a_section_written_as_bandit(
    retired_oldname, tmp_path, monkeypatch, operation, refusal
):
    """The base writes bandit's section under bandit, enabled: false, and the
    child's patch removes, replaces or tests /scanners/oldname or a path under
    it. No file wrote oldname, so the pointer is oldname's own key, which the
    document does not hold, and the load is refused."""
    from automated_security_helper.core.exceptions import ASHConfigSourceError

    child = _child_patching_its_base(
        tmp_path, {"bandit": {"enabled": False}}, operation
    )

    with pytest.raises(ASHConfigSourceError) as refused:
        _load(monkeypatch, child)

    text = " ".join(str(refused.value).split())
    assert "'patch' entry 0 in" in text, text
    assert refusal in text, text


def test_a_childs_add_under_the_retired_name_lays_over_a_section_written_as_bandit(
    retired_oldname, tmp_path, monkeypatch
):
    """The base writes bandit's section under bandit, enabled: false and
    confidence_level: high, and the child's patch adds /scanners/oldname with
    confidence_level: low. No file wrote oldname, so the add writes oldname's
    own section, which the loader folds over bandit's key by key:
    confidence_level is the add's low, and the base's enabled: false stays."""
    child = _child_patching_its_base(
        tmp_path,
        {"bandit": {"enabled": False, "options": {"confidence_level": "high"}}},
        {
            "op": "add",
            "path": "/scanners/oldname",
            "value": {"options": {"confidence_level": "low"}},
        },
    )

    config = _load(monkeypatch, child)

    assert config.scanners.bandit.enabled is False
    assert config.scanners.bandit.options.confidence_level == "low"


# A child's ``patch`` naming a section that it and its base both write. Each
# file's own section is folded onto bandit's as the file is read, so the merged
# document holds one bandit section with what both files wrote, and a pointer
# in the retired spelling reaches every part of it. The canonical-control rows
# write bandit in both files, with the same row planted.

_SECTION_IDS = ["retired-name", "canonical-control"]


def _child_writing_and_patching(tmp_path, base_scanners, child_scanners, *ops):
    _write(tmp_path / "base.yaml", {"scanners": base_scanners})
    return _write(
        tmp_path / "child.yaml",
        {"extends": "base.yaml", "scanners": child_scanners, "patch": list(ops)},
    )


@pytest.mark.parametrize("section", ["oldname", "bandit"], ids=_SECTION_IDS)
@pytest.mark.parametrize("op, expected", [("remove", "all"), ("replace", "low")])
def test_a_childs_op_inside_a_section_both_files_write_reaches_the_bases_option(
    retired_oldname, tmp_path, monkeypatch, section, op, expected
):
    """The base writes enabled and confidence_level, the child writes enabled,
    both under *section*, and the child's patch removes or replaces
    /scanners/<section>/options/confidence_level, which only the base wrote.
    The load succeeds and the op applies to bandit's section: confidence_level
    is bandit's default or the op's value, and enabled is the child's."""
    operation: dict = {
        "op": op,
        "path": f"/scanners/{section}/options/confidence_level",
    }
    if op == "replace":
        operation["value"] = "low"
    child = _child_writing_and_patching(
        tmp_path,
        {section: {"enabled": False, "options": {"confidence_level": "high"}}},
        {section: {"enabled": True}},
        operation,
    )

    config = _load(monkeypatch, child)

    assert config.scanners.bandit.enabled is True
    assert config.scanners.bandit.options.confidence_level == expected


@pytest.mark.parametrize("section", ["oldname", "bandit"], ids=_SECTION_IDS)
@pytest.mark.parametrize("op", ["remove", "replace"])
@pytest.mark.parametrize("written_by", ["base", "child"])
def test_a_childs_op_at_a_sub_path_one_file_writes_reaches_it(
    retired_oldname, tmp_path, monkeypatch, section, op, written_by
):
    """The base writes enabled: false and the child confidence_level: high,
    both under *section*, and the child's patch removes or replaces the one
    the row names. The load succeeds and the op applies to bandit's section:
    enabled is bandit's default or the op's true, or confidence_level is
    bandit's default or the op's low, and the other setting is the one its
    file wrote. The ``child`` rows are controls: the child's own section holds
    the sub-path, so the op reaches it whether or not that section is folded
    before the patch applies."""
    if written_by == "base":
        path, value = f"/scanners/{section}/enabled", True
    else:
        path, value = f"/scanners/{section}/options/confidence_level", "low"
    operation: dict = {"op": op, "path": path}
    if op == "replace":
        operation["value"] = value
    child = _child_writing_and_patching(
        tmp_path,
        {section: {"enabled": False}},
        {section: {"options": {"confidence_level": "high"}}},
        operation,
    )

    config = _load(monkeypatch, child)

    bandit = config.scanners.bandit
    if written_by == "base":
        assert bandit.enabled is True
        assert bandit.options.confidence_level == "high"
    else:
        assert bandit.enabled is False
        assert bandit.options.confidence_level == ("all" if op == "remove" else "low")


@pytest.mark.parametrize("section", ["oldname", "bandit"], ids=_SECTION_IDS)
@pytest.mark.parametrize("op", ["add", "replace", "remove"])
def test_a_childs_op_on_a_whole_section_both_files_write_takes_all_of_it(
    retired_oldname, tmp_path, monkeypatch, section, op
):
    """The base writes enabled: false and confidence_level: high, the child
    writes enabled: true, both under *section*, and the child's patch adds,
    replaces or removes /scanners/<section>. The op takes bandit's whole
    section, and nothing the base wrote is merged back under it: after an add
    or a replace bandit holds only the op's value (enabled is bandit's
    default, true, and confidence_level the op's low), and after a remove it
    holds bandit's defaults."""
    operation: dict = {"op": op, "path": f"/scanners/{section}"}
    if op != "remove":
        operation["value"] = {"options": {"confidence_level": "low"}}
    child = _child_writing_and_patching(
        tmp_path,
        {section: {"enabled": False, "options": {"confidence_level": "high"}}},
        {section: {"enabled": True}},
        operation,
    )

    config = _load(monkeypatch, child)

    assert config.scanners.bandit.enabled is True
    assert config.scanners.bandit.options.confidence_level == (
        "all" if op == "remove" else "low"
    )


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


# Where the fold is logged. The loader folds each file's own retired sections
# as it reads the file, so the line comes from the loader, once for each
# document it folds, and the model finds nothing left to fold.

_FOLD_LINE = (
    "scanners.oldname is an alias of the bandit plugin; "
    "applying its section to scanners.bandit"
)


def _fold_lines(caplog):
    return [r.getMessage() for r in caplog.records if _FOLD_LINE in r.getMessage()]


@pytest.mark.parametrize("chain", ["one-file", "base-and-child"])
def test_the_loader_folds_and_logs_each_files_retired_section_once(
    retired_oldname, tmp_path, monkeypatch, caplog, chain
):
    """The loader alone (resolve_config_document, no model) folds each file's
    own section under the retired name onto bandit's, and logs the fold once
    for each document it folds: one line for one file, two for a child and a
    base that both write the retired name. The model, given the folded
    document, logs no fold."""
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.config_sources import (
        resolve_config_document,
    )

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    if chain == "one-file":
        path = _write(
            tmp_path / "one.yaml", {"scanners": {"oldname": {"enabled": False}}}
        )
        folded_documents = 1
    else:
        _write(tmp_path / "base.yaml", {"scanners": {"oldname": {"enabled": True}}})
        path = _write(
            tmp_path / "child.yaml",
            {"extends": "base.yaml", "scanners": {"oldname": {"enabled": False}}},
        )
        folded_documents = 2

    with caplog.at_level(logging.INFO, logger="ash"):
        document = resolve_config_document(path)

    assert document.data["scanners"] == {"bandit": {"enabled": False}}
    assert len(_fold_lines(caplog)) == folded_documents, _fold_lines(caplog)

    caplog.clear()
    with caplog.at_level(logging.INFO, logger="ash"):
        config = AshConfig.model_validate(document.data)

    assert config.scanners.bandit.enabled is False
    assert _fold_lines(caplog) == []


def test_a_load_through_the_model_logs_a_files_fold_once(
    retired_oldname, tmp_path, monkeypatch, caplog
):
    """The control: AshConfig.from_file reads the file and validates it, and
    the fold of its section under the retired name is logged once for the
    load."""
    path = _write(tmp_path / "one.yaml", {"scanners": {"oldname": {"enabled": False}}})

    with caplog.at_level(logging.INFO, logger="ash"):
        config = _load(monkeypatch, path)

    assert config.scanners.bandit.enabled is False
    assert len(_fold_lines(caplog)) == 1, _fold_lines(caplog)


# A value a file reads from the environment under the retired name. The loader
# pairs the file's two readings before the fold, so every read is found, and
# then moves each reference to the place the fold gives its value: the
# results file's record and MCP get_config find it at bandit's section, where
# the configuration holds the value. The canonical-control rows write bandit,
# with the same row planted.

_FOLD_VAR = "ASH_TEST_RETIRED_FOLD_VALUE"
_FOLD_VALUE = "retired-fold-format-7c3e"
# Not a name ending in _KEY: a config file may not read a variable whose name
# ends in a credential suffix (core/constants.ASH_CONFIG_ENV_VAR_SECRET_SUFFIXES),
# and the loader would leave the key as written.
_FOLD_KEY_VAR = "ASH_TEST_RETIRED_FOLD_SECTION"


def _child_reading_the_environment(tmp_path, section):
    """A child that extends a base writing the retired name, and writes the
    variable as the one entry of bandit's additional_formats under
    *section*."""
    _write(tmp_path / "base.yaml", {"scanners": {"oldname": {"enabled": False}}})
    child = tmp_path / "child.yaml"
    child.write_text(
        "extends: base.yaml\n"
        f"scanners:\n  {section}:\n    options:\n"
        f"      additional_formats:\n        - ${{{_FOLD_VAR}}}\n",
        encoding="utf-8",
    )
    return child


def _named_by_the_operator(tmp_path, monkeypatch):
    """Set the test's directory aside as the operator's, so MCP get_config
    reads a file there as the operator's own (ASH_MCP_ALLOWED_CONFIG_ROOTS),
    from a working directory in no checkout."""
    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(tmp_path))
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)


def _record(config):
    """The results file's ash_config for *config*."""
    import json

    from automated_security_helper.models.asharp_model import AshAggregatedResults

    return json.loads(
        AshAggregatedResults(ash_config=config).model_dump_json(by_alias=True)
    )["ash_config"]


def _bandit_section(scanners, key_shown):
    """bandit's section in *scanners*, a dump's or a record's: under bandit, or
    under *key_shown* where the file read the key ``bandit`` from the
    environment and the dump shows that key by its reference."""
    return scanners["bandit"] if "bandit" in scanners else scanners[key_shown]


@pytest.mark.parametrize("section", ["oldname", "bandit"], ids=_SECTION_IDS)
def test_get_config_shows_a_value_read_under_the_retired_name_by_its_reference(
    retired_oldname, tmp_path, monkeypatch, section
):
    """The child writes ${VAR} as bandit's additional_formats under *section*.
    MCP get_config shows the entry at bandit's section as `<from ${VAR}>`,
    beside the base's enabled, and the variable's value appears nowhere in
    the answer."""
    import json

    from automated_security_helper.cli.mcp_tools import mcp_get_config

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv(_FOLD_VAR, _FOLD_VALUE)
    child = _child_reading_the_environment(tmp_path, section)
    _named_by_the_operator(tmp_path, monkeypatch)

    result = mcp_get_config(config_path=str(child))

    assert _FOLD_VALUE not in json.dumps(result), result
    bandit = result["scanners"]["bandit"]
    assert bandit["enabled"] is False, bandit
    assert bandit["options"]["additional_formats"] == [f"<from ${{{_FOLD_VAR}}}>"]


@pytest.mark.parametrize("section", ["oldname", "bandit"], ids=_SECTION_IDS)
def test_the_results_record_keeps_a_retired_name_s_value_as_its_reference(
    retired_oldname, tmp_path, monkeypatch, section
):
    """The same chain, loaded as a scan loads it: the configuration holds the
    value, and the results file's ash_config holds the entry at bandit's
    section as the reference the child wrote, ${VAR}, and no resolved value
    of it."""
    import json

    from automated_security_helper.config.resolve_config import (
        load_config_file_for_run,
    )

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv(_FOLD_VAR, _FOLD_VALUE)

    _, config = load_config_file_for_run(
        _child_reading_the_environment(tmp_path, section)
    )

    assert config.scanners.bandit.options.additional_formats == [_FOLD_VALUE]
    record = _record(config)
    assert _FOLD_VALUE not in json.dumps(record), record.get("scanners")
    options = record["scanners"]["bandit"]["options"]
    assert options["additional_formats"] == [f"${{{_FOLD_VAR}}}"], options


@pytest.mark.parametrize("section", ["oldname", "bandit"], ids=_SECTION_IDS)
def test_a_section_key_read_from_the_environment_keeps_its_references(
    retired_oldname, tmp_path, monkeypatch, section
):
    """The file writes the section's key as ${KEY}, which reads *section*,
    and ${VAR} as additional_formats under it. The loader pairs the key with
    the name it resolved to before the fold, so the entry's reference is
    found, and moves it to bandit's section: the results file's ash_config
    holds the entry as ${VAR}, MCP get_config shows it as `<from ${VAR}>`,
    and neither holds the variable's value. Where the key reads bandit (the
    canonical-control row), the record and the answer show the key by its
    reference too."""
    import json

    from automated_security_helper.cli.mcp_tools import mcp_get_config
    from automated_security_helper.config.ash_config import (
        config_env_var_is_interpolatable,
    )
    from automated_security_helper.config.resolve_config import (
        load_config_file_for_run,
    )

    # The premise: a config file may read both variables.
    assert config_env_var_is_interpolatable(_FOLD_KEY_VAR)
    assert config_env_var_is_interpolatable(_FOLD_VAR)

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv(_FOLD_VAR, _FOLD_VALUE)
    monkeypatch.setenv(_FOLD_KEY_VAR, section)
    path = tmp_path / "keyed.yaml"
    path.write_text(
        f"scanners:\n  ${{{_FOLD_KEY_VAR}}}:\n    enabled: false\n"
        f"    options:\n      additional_formats:\n        - ${{{_FOLD_VAR}}}\n",
        encoding="utf-8",
    )

    _, config = load_config_file_for_run(path)

    assert config.scanners.bandit.enabled is False
    record = _record(config)
    assert _FOLD_VALUE not in json.dumps(record), record.get("scanners")
    recorded = _bandit_section(record["scanners"], f"${{{_FOLD_KEY_VAR}}}")
    assert recorded["options"]["additional_formats"] == [f"${{{_FOLD_VAR}}}"]

    _named_by_the_operator(tmp_path, monkeypatch)
    result = mcp_get_config(config_path=str(path))

    assert _FOLD_VALUE not in json.dumps(result), result
    shown = _bandit_section(result["scanners"], f"<from ${{{_FOLD_KEY_VAR}}}>")
    assert shown["enabled"] is False, shown
    assert shown["options"]["additional_formats"] == [f"<from ${{{_FOLD_VAR}}}>"]


@pytest.mark.parametrize("section", ["oldname", "bandit"], ids=_SECTION_IDS)
def test_an_option_bandit_does_not_declare_under_the_retired_name_leaves_no_value(
    retired_oldname, tmp_path, monkeypatch, section
):
    """The file writes ${VAR} at retired_only_knob, an option bandit's options
    do not declare, under *section*. Under the retired name the fold drops the
    option before anything is recorded, so its value appears nowhere: not in
    the configuration, not among the references and rewrites the load
    records, not in the results file's ash_config, and not in MCP
    get_config's answer. The canonical-control row writes the option under
    bandit, where no fold drops it: the load is refused for an option bandit
    does not declare, and the refusal names the option and does not hold the
    variable's value."""
    import json

    from automated_security_helper.cli.mcp_tools import mcp_get_config
    from automated_security_helper.config.resolve_config import (
        ConfigFileRefused,
        load_config_file_for_run,
    )

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv(_FOLD_VAR, _FOLD_VALUE)
    path = tmp_path / "knob.yaml"
    path.write_text(
        f"scanners:\n  {section}:\n    options:\n"
        f"      retired_only_knob: ${{{_FOLD_VAR}}}\n",
        encoding="utf-8",
    )

    if section == "bandit":
        with pytest.raises(ConfigFileRefused) as refused:
            load_config_file_for_run(path)
        text = str(refused.value)
        assert "Unknown key 'retired_only_knob'" in text, text
        assert _FOLD_VALUE not in text, text
        return

    _, config = load_config_file_for_run(path)

    record = _record(config)
    assert _FOLD_VALUE not in json.dumps(record), record.get("scanners")
    assert not hasattr(config.scanners.bandit.options, "retired_only_knob")
    assert _FOLD_VALUE not in json.dumps(config.model_dump(mode="json"))
    references = [
        reference
        for reference in (
            *config._environment_references,
            *config._displayed_environment_references,
        )
        if _FOLD_VALUE in (reference.resolved, reference.value)
    ]
    assert references == [], references
    rewrites = [
        rewrite
        for rewrite in config._written_references or []
        if rewrite.resolved == _FOLD_VALUE
    ]
    assert rewrites == [], rewrites

    _named_by_the_operator(tmp_path, monkeypatch)
    result = mcp_get_config(config_path=str(path))

    assert _FOLD_VALUE not in json.dumps(result), result


# An option bandit does not declare, written under the retired name, is dropped
# as the file is read, before the file's own patch applies. An operation that
# removes, replaces or tests it then finds nothing there: the load is refused,
# and the refusal says the option was dropped. Under bandit no fold drops it,
# so the same operation applies, and an option bandit does not declare is then
# refused as it is in any file.

_DROPPED_CLAUSE = (
    "The option it names was dropped when the file that wrote it was read: it "
    "is written under a retired scanner name, and the bandit plugin that serves "
    "that name does not declare it."
)


def _file_patching_its_own_knob(tmp_path, section, op):
    """A file that writes retired_only_knob under *section* and whose own patch
    applies *op* (remove, replace or test) to it."""
    operation: dict = {
        "op": op,
        "path": f"/scanners/{section}/options/retired_only_knob",
    }
    if op != "remove":
        operation["value"] = 1
    return _write(
        tmp_path / "knob.yaml",
        {
            "scanners": {section: {"options": {"retired_only_knob": 1}}},
            "patch": [operation],
        },
    )


@pytest.mark.parametrize("op", ["remove", "replace", "test"])
def test_an_op_on_an_option_the_retired_name_fold_dropped_is_refused_with_its_cause(
    retired_oldname, tmp_path, monkeypatch, op
):
    """The file writes retired_only_knob, an option bandit's options do not
    declare, under oldname, and its own patch removes, replaces or tests it.
    The fold dropped the option as the file was read, so the operation finds
    nothing: the load is refused, and the message names the cause."""
    from automated_security_helper.core.exceptions import ASHConfigSourceError

    path = _file_patching_its_own_knob(tmp_path, "oldname", op)

    with pytest.raises(ASHConfigSourceError) as refused:
        _load(monkeypatch, path)

    text = " ".join(str(refused.value).split())
    assert "'patch' entry 0 in" in text, text
    assert _DROPPED_CLAUSE in text, text


@pytest.mark.parametrize("op", ["remove", "replace", "test"])
def test_an_op_on_an_option_bandit_does_not_declare_under_bandit_applies(
    retired_oldname, tmp_path, monkeypatch, op
):
    """The control: under bandit no fold drops the option, so the same
    operation applies. A remove takes the option out, and the load succeeds
    without it. After a replace or a test the option is still there, and the
    load is refused as for any option bandit does not declare: the refusal
    names the option, says nothing of a dropped option, and does not refuse
    the patch entry."""
    from automated_security_helper.config.resolve_config import ConfigFileRefused

    path = _file_patching_its_own_knob(tmp_path, "bandit", op)

    if op == "remove":
        config = _load(monkeypatch, path)
        assert not hasattr(config.scanners.bandit.options, "retired_only_knob")
        return

    with pytest.raises(ConfigFileRefused) as refused:
        _load(monkeypatch, path)

    text = " ".join(str(refused.value).split())
    assert "Unknown key 'retired_only_knob'" in text, text
    assert _DROPPED_CLAUSE not in text, text
    assert "'patch' entry 0 in" not in text, text


# A patch's add or replace under the retired name, in a chain that wrote the
# section under that name, lands on bandit's section, so its value is written
# there without passing the fold the file's own section passed. The value is
# held to the fold's rules instead: the section's name and the options bandit
# does not declare are dropped from it, with one warning that names bandit and
# no key the file wrote, and a write of either alone writes nothing. Each
# retired-name row was refused while the value was written as it stood.

_PATCH_DROP_PREFIX = "A patch operation under a retired scanner name writes "


def _patch_drop_lines(caplog):
    return [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith(_PATCH_DROP_PREFIX)
    ]


def _patched_file(tmp_path, section, *ops, chain="one-file"):
    """A file that writes confidence_level: high under *section* and applies
    *ops* in its own patch; with *chain* "base-and-child", that file is a base
    and a child that extends it applies *ops* instead."""
    written = {"scanners": {section: {"options": {"confidence_level": "high"}}}}
    if chain == "one-file":
        return _write(tmp_path / "patched.yaml", {**written, "patch": list(ops)})
    _write(tmp_path / "base.yaml", written)
    return _write(tmp_path / "child.yaml", {"extends": "base.yaml", "patch": list(ops)})


def _loaded(path, caplog):
    """The loader's document for *path*, the patch-drop warnings it logged,
    and the configuration the model makes of the document."""
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.config_sources import (
        resolve_config_document,
    )

    with caplog.at_level(logging.INFO, logger="ash"):
        document = resolve_config_document(path)
    lines = _patch_drop_lines(caplog)
    return document, lines, AshConfig.model_validate(document.data)


@pytest.mark.parametrize("chain", ["one-file", "base-and-child"])
@pytest.mark.parametrize("section", ["oldname", "bandit"], ids=_SECTION_IDS)
def test_an_add_of_an_option_bandit_does_not_declare_under_the_retired_name_drops_it(
    retired_oldname, tmp_path, monkeypatch, caplog, section, chain
):
    """The patch adds retired_only_knob, an option bandit's options do not
    declare, under *section*, in the file that writes the section or in a
    child of it. Under the retired name the pointer lands on bandit's section
    and the fold's rule drops the option: the load succeeds, bandit keeps the
    file's confidence_level, the option is not there, and one warning names
    bandit and the drop and no key the file wrote. The canonical-control row
    adds it under bandit, where no fold drops it: the load is refused for an
    option bandit does not declare."""
    from automated_security_helper.config.resolve_config import ConfigFileRefused

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    path = _patched_file(
        tmp_path,
        section,
        {
            "op": "add",
            "path": f"/scanners/{section}/options/retired_only_knob",
            "value": 1,
        },
        chain=chain,
    )

    if section == "bandit":
        with pytest.raises(ConfigFileRefused) as refused:
            _load(monkeypatch, path)
        text = " ".join(str(refused.value).split())
        assert "Unknown key 'retired_only_knob'" in text, text
        return

    document, lines, config = _loaded(path, caplog)

    options = document.data["scanners"]["bandit"]["options"]
    assert options == {"confidence_level": "high"}, options
    assert config.scanners.bandit.options.confidence_level == "high"
    assert not hasattr(config.scanners.bandit.options, "retired_only_knob")
    assert len(lines) == 1, lines
    assert "bandit" in lines[0] and "dropped" in lines[0], lines
    assert "retired_only_knob" not in lines[0], lines


@pytest.mark.parametrize("op", ["add", "replace"])
def test_a_patched_section_under_the_retired_name_drops_name_and_undeclared_options(
    retired_oldname, tmp_path, monkeypatch, caplog, op
):
    """The patch adds or replaces the whole section under oldname, the
    section the file wrote under that name, with a value that holds
    name: oldname, enabled: false, confidence_level: low and
    retired_only_knob. The pointer lands on bandit's section, which the value
    replaces, and the fold's rules drop the name and the option bandit does
    not declare: the load succeeds with bandit's own name, enabled false and
    confidence_level low, the option is not there, and one warning names the
    drop."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    path = _patched_file(
        tmp_path,
        "oldname",
        {
            "op": op,
            "path": "/scanners/oldname",
            "value": {
                "name": "oldname",
                "enabled": False,
                "options": {"confidence_level": "low", "retired_only_knob": 1},
            },
        },
    )

    document, lines, config = _loaded(path, caplog)

    section = document.data["scanners"]["bandit"]
    assert section == {"enabled": False, "options": {"confidence_level": "low"}}
    assert config.scanners.bandit.name == "bandit"
    assert config.scanners.bandit.enabled is False
    assert config.scanners.bandit.options.confidence_level == "low"
    assert not hasattr(config.scanners.bandit.options, "retired_only_knob")
    assert len(lines) == 1 and "dropped" in lines[0], lines


@pytest.mark.parametrize("op", ["add", "replace"])
def test_patched_options_under_the_retired_name_drop_undeclared_keys(
    retired_oldname, tmp_path, monkeypatch, caplog, op
):
    """The patch adds or replaces oldname's options with confidence_level: low
    and retired_only_knob. The pointer lands on bandit's options, and the
    fold's rule drops the option bandit does not declare: the load succeeds
    with confidence_level low, the option is not there, and one warning names
    the drop."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    path = _patched_file(
        tmp_path,
        "oldname",
        {
            "op": op,
            "path": "/scanners/oldname/options",
            "value": {"confidence_level": "low", "retired_only_knob": 1},
        },
    )

    document, lines, config = _loaded(path, caplog)

    options = document.data["scanners"]["bandit"]["options"]
    assert options == {"confidence_level": "low"}, options
    assert config.scanners.bandit.options.confidence_level == "low"
    assert not hasattr(config.scanners.bandit.options, "retired_only_knob")
    assert len(lines) == 1 and "dropped" in lines[0], lines


@pytest.mark.parametrize("op", ["add", "replace"])
def test_a_patched_section_name_under_the_retired_name_writes_nothing(
    retired_oldname, tmp_path, monkeypatch, caplog, op
):
    """The patch adds or replaces oldname's name. The fold drops a section's
    name under a retired name, so the operation writes nothing: the load
    succeeds with bandit's own name and the file's options, and no warning
    names a drop. Written as it stood, the add set bandit's name to oldname,
    which bandit refuses, and the replace found no name in bandit's section."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    path = _patched_file(
        tmp_path,
        "oldname",
        {"op": op, "path": "/scanners/oldname/name", "value": "oldname"},
    )

    document, lines, config = _loaded(path, caplog)

    section = document.data["scanners"]["bandit"]
    assert section == {"options": {"confidence_level": "high"}}, section
    assert config.scanners.bandit.name == "bandit"
    assert lines == [], lines


def test_an_undeclared_option_a_patch_writes_under_the_retired_name_leaves_no_value(
    retired_oldname, tmp_path, monkeypatch
):
    """The file writes confidence_level under oldname, and its patch adds the
    whole section under oldname with confidence_level: low and ${VAR} at
    retired_only_knob, an option bandit does not declare. The pointer lands
    on bandit's section and the fold's rule drops the option, in the
    configuration and in the copy the references are followed through, so
    the variable's value appears nowhere: not in the configuration, not among
    the references and rewrites the load records, not in the results file's
    ash_config, and not in MCP get_config's answer."""
    import json

    from automated_security_helper.cli.mcp_tools import mcp_get_config
    from automated_security_helper.config.resolve_config import (
        load_config_file_for_run,
    )

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv(_FOLD_VAR, _FOLD_VALUE)
    path = tmp_path / "patched.yaml"
    path.write_text(
        "scanners:\n  oldname:\n    options:\n      confidence_level: high\n"
        "patch:\n"
        "  - op: add\n"
        "    path: /scanners/oldname\n"
        "    value:\n"
        "      options:\n"
        "        confidence_level: low\n"
        f"        retired_only_knob: ${{{_FOLD_VAR}}}\n",
        encoding="utf-8",
    )

    _, config = load_config_file_for_run(path)

    assert config.scanners.bandit.options.confidence_level == "low"
    assert not hasattr(config.scanners.bandit.options, "retired_only_knob")
    assert _FOLD_VALUE not in json.dumps(config.model_dump(mode="json"))
    references = [
        reference
        for reference in (
            *config._environment_references,
            *config._displayed_environment_references,
        )
        if _FOLD_VALUE in (reference.resolved, reference.value)
    ]
    assert references == [], references
    rewrites = [
        rewrite
        for rewrite in config._written_references or []
        if rewrite.resolved == _FOLD_VALUE
    ]
    assert rewrites == [], rewrites
    record = _record(config)
    assert _FOLD_VALUE not in json.dumps(record), record.get("scanners")

    _named_by_the_operator(tmp_path, monkeypatch)
    result = mcp_get_config(config_path=str(path))

    assert _FOLD_VALUE not in json.dumps(result), result


def test_an_option_key_a_patch_reads_under_the_retired_name_keeps_its_reference(
    retired_oldname, tmp_path, monkeypatch
):
    """The patch adds the whole section with the option's key read from the
    environment, ${KEY}, which reads confidence_level, a name bandit
    declares. Under the retired name the pointer lands on bandit's section
    and the fold's rule keeps the option, so the load records the key's
    reference where it records it when the same patch adds the section under
    bandit, the canonical control no fold touches: the two loads record the
    same key references, and there is one."""
    from automated_security_helper.config.ash_config import (
        config_env_var_is_interpolatable,
    )
    from automated_security_helper.config.resolve_config import (
        load_config_file_for_run,
    )

    # The premise: a config file may read the variable.
    assert config_env_var_is_interpolatable(_FOLD_KEY_VAR)

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv(_FOLD_KEY_VAR, "confidence_level")

    def loaded(section):
        folder = tmp_path / section
        folder.mkdir()
        path = folder / "patched.yaml"
        path.write_text(
            "scanners:\n  oldname:\n    enabled: true\n"
            "patch:\n"
            "  - op: add\n"
            f"    path: /scanners/{section}\n"
            "    value:\n"
            "      options:\n"
            f"        ${{{_FOLD_KEY_VAR}}}: low\n",
            encoding="utf-8",
        )
        _, config = load_config_file_for_run(path)
        return config

    def key_references(config):
        return sorted(
            (tuple(map(str, reference.path)), reference.resolved)
            for reference in (
                *config._environment_references,
                *config._displayed_environment_references,
            )
            if reference.key
        )

    retired, canonical = loaded("oldname"), loaded("bandit")

    assert retired.scanners.bandit.options.confidence_level == "low"
    assert canonical.scanners.bandit.options.confidence_level == "low"
    assert key_references(canonical), key_references(canonical)
    assert key_references(retired) == key_references(canonical), (
        key_references(retired),
        key_references(canonical),
    )


# A value read from the environment in a section a ``patch`` adds under the
# retired name. The loader folds the added section onto bandit's once the patch
# has applied and moves the reference with its value, so the results file's
# record and MCP get_config show the value by its reference, as under bandit.
# The canonical-control rows add the section under bandit.


def _patch_adding_a_value_read_from_the_environment(tmp_path, section, *, from_base):
    """A file whose patch adds bandit's section under *section*, with the
    variable as the one entry of additional_formats; with *from_base*, that
    file is a base, and the file returned extends it."""
    patched = tmp_path / ("base.yaml" if from_base else "patched.yaml")
    patched.write_text(
        "scanners: {}\n"
        "patch:\n"
        "  - op: add\n"
        f"    path: /scanners/{section}\n"
        "    value:\n"
        "      options:\n"
        "        additional_formats:\n"
        f"          - ${{{_FOLD_VAR}}}\n",
        encoding="utf-8",
    )
    if not from_base:
        return patched
    return _write(tmp_path / "child.yaml", {"extends": "base.yaml"})


@pytest.mark.parametrize("from_base", [False, True], ids=["the-file", "its-base"])
@pytest.mark.parametrize("section", ["oldname", "bandit"], ids=_SECTION_IDS)
def test_a_value_a_patch_adds_under_the_retired_name_is_shown_by_its_reference(
    retired_oldname, tmp_path, monkeypatch, section, from_base
):
    """The patch adds ${VAR} under *section*, in the file loaded or in its
    base. The configuration holds the value at bandit's section, the results
    file's ash_config holds the reference there, MCP get_config shows it as
    `<from ${VAR}>`, and neither holds the value."""
    import json

    from automated_security_helper.cli.mcp_tools import mcp_get_config
    from automated_security_helper.config.resolve_config import (
        load_config_file_for_run,
    )

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv(_FOLD_VAR, _FOLD_VALUE)
    path = _patch_adding_a_value_read_from_the_environment(
        tmp_path, section, from_base=from_base
    )

    _, config = load_config_file_for_run(path)

    assert config.scanners.bandit.options.additional_formats == [_FOLD_VALUE]
    record = _record(config)
    assert _FOLD_VALUE not in json.dumps(record), record.get("scanners")
    options = record["scanners"]["bandit"]["options"]
    assert options["additional_formats"] == [f"${{{_FOLD_VAR}}}"], options

    _named_by_the_operator(tmp_path, monkeypatch)
    result = mcp_get_config(config_path=str(path))

    assert _FOLD_VALUE not in json.dumps(result), result
    shown = result["scanners"]["bandit"]["options"]["additional_formats"]
    assert shown == [f"<from ${{{_FOLD_VAR}}}>"], shown


def test_the_fold_records_the_sections_it_moved_and_the_options_it_dropped(
    retired_oldname,
):
    """``folds`` gets, for each plugin a retired name's section was laid onto,
    the option keys the fold dropped: what the loader reads to redirect a
    patch pointer and to say why an operation found nothing. A mapping with
    no retired name records nothing."""
    from automated_security_helper.config.ash_config import (
        fold_scanner_name_aliases,
    )

    record: dict = {}
    folded = fold_scanner_name_aliases(
        {"oldname": {"options": {"confidence_level": "high", "retired_only_knob": 1}}},
        folds=record,
        log=False,
    )

    assert folded == {"bandit": {"options": {"confidence_level": "high"}}}
    assert record == {"bandit": {"retired_only_knob"}}

    untouched: dict = {}
    fold_scanner_name_aliases({"bandit": {"enabled": True}}, folds=untouched, log=False)
    assert untouched == {}


def test_the_fold_reads_the_options_a_plugin_declares_under_its_alias():
    """detect-secrets' section key is its field's alias (the field is
    detect_secrets). The fold reads that plugin's declared options too, so an
    option it does not declare is dropped from a section written under a
    retired name it serves, as for bandit."""
    from automated_security_helper.config.ash_config import (
        ScannerConfigSegment,
        _declared_option_names,
    )

    declared = _declared_option_names(ScannerConfigSegment, "detect-secrets")

    assert declared is not None
    assert "max_worker_output_mib" in declared
