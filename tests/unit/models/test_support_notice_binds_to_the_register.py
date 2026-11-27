"""The words of a support notice are the support register's words.

Why this exists
---------------
``SupportNotice`` spells the vocabularies it is written in (level, behavior, the kind
and group of an upgrade path, the moment a notice was raised, and the names of the
facts it records) as text types of its own. It cannot take them from
``base/support_register.py``: the register builds and checks every declaration it
holds when it is imported, and a results file has to load without that, because
``ash report`` and ``ash merge`` read notices and never evaluate a row. So the two are
held equal here. A member added to or taken out of one of the register's enums, or a
fact added to or taken out of its ``FIELDS``, and not mirrored in the model, fails the
first group of tests; a row the register declares that the model could not hold fails
the second.

The register's ``Notify.MATRIX`` and ``SupportLevel.SUPPORTED`` are the two members a
notice never has: a matrix-only row is shown in the matrices and on the docs page and
never raised, and a supported row says nothing.
"""

import enum
from typing import get_args

import pytest
from pydantic import BaseModel, ValidationError

from automated_security_helper.base.support_register import (
    FIELDS,
    REGISTER,
    Behavior,
    Notify,
    PathKind,
    SupportLevel,
)
from automated_security_helper.models.asharp_model import (
    SupportNotice,
    UpgradePathNotice,
)
from tests.unit.models._support_notice_helpers import (
    cpu_notice,
    notice_of_row,
    upgrade_path,
)

pytestmark = pytest.mark.unit


def _words(model: type, name: str) -> set[str]:
    """The words a field of ``model`` accepts, read from its declared type."""
    return set(get_args(model.model_fields[name].annotation))


def _drift(words: set[str], enum_type: type[enum.Enum], never: set[str]) -> dict:
    """What differs between a model's words and an enum's members.

    ``never`` names the members a notice does not have. The answer is empty when the
    two agree; ``missing`` is what the register has and the model refuses, ``extra``
    what the model takes and the register does not know.
    """
    members = {member.value for member in enum_type} - never
    return {"missing": members - words, "extra": words - members}


NO_DRIFT = {"missing": set(), "extra": set()}


def _fact_names(model: type) -> set[str]:
    """The fact names a model's ``facts`` accepts, read from the key type of the field.

    A field typed ``Dict[str, str]`` has no names to read, so a model that took any
    name for a fact reads as accepting none of the register's, and the comparison
    below says so.
    """
    key_type, _value_type = get_args(model.model_fields["facts"].annotation)
    return set(get_args(key_type))


def _name_drift(names: set[str], declared: tuple[str, ...]) -> dict:
    """What differs between the names a model accepts and the register's facts.

    ``missing`` is what the register declares and the model refuses, ``extra`` what the
    model takes and the register does not know. Both are empty when the two agree.
    """
    return {"missing": set(declared) - names, "extra": names - set(declared)}


class TestTheVocabulariesAreTheRegistersEnums:
    def test_level(self):
        assert (
            _drift(
                _words(SupportNotice, "level"),
                SupportLevel,
                {SupportLevel.SUPPORTED.value},
            )
            == NO_DRIFT
        )

    def test_behavior(self):
        assert _drift(_words(SupportNotice, "behavior"), Behavior, set()) == NO_DRIFT

    def test_the_moment_a_notice_was_raised(self):
        assert (
            _drift(_words(SupportNotice, "raised"), Notify, {Notify.MATRIX.value})
            == NO_DRIFT
        )

    def test_kind_of_an_upgrade_path(self):
        assert _drift(_words(UpgradePathNotice, "kind"), PathKind, set()) == NO_DRIFT

    def test_the_two_groups_split_the_kinds_as_the_register_does(self):
        assert _words(UpgradePathNotice, "group") == {"this-machine", "elsewhere"}
        for kind in PathKind:
            group = "this-machine" if kind.here else "elsewhere"
            upgrade_path("probe", kind.value, "Do the probe.", group=group)

    def test_the_comparison_flags_a_member_the_model_lacks(self):
        """Must-flag: the same comparison against an enum with one more member, and
        against one with one fewer, is not empty. Without this a comparison that
        compared nothing would pass."""

        class MoreLevels(str, enum.Enum):
            POLYFILLED = "polyfilled"
            DEGRADED = "degraded"
            UNSUPPORTED = "unsupported"
            RETIRED = "retired"

        class FewerLevels(str, enum.Enum):
            POLYFILLED = "polyfilled"
            DEGRADED = "degraded"

        words = _words(SupportNotice, "level")

        assert _drift(words, MoreLevels, set()) == {
            "missing": {"retired"},
            "extra": set(),
        }
        assert _drift(words, FewerLevels, set()) == {
            "missing": set(),
            "extra": {"unsupported"},
        }


class TestTheFactNamesAreTheRegistersFields:
    def test_the_names_a_notice_accepts_are_the_registers_fields(self):
        assert _name_drift(_fact_names(SupportNotice), FIELDS) == NO_DRIFT

    def test_the_comparison_flags_a_name_the_model_lacks_and_one_it_adds(self):
        """Must-flag: the same comparison of a model that holds exactly the register's
        names, against a register with one more fact and against one with one fewer,
        is not empty. Without this a comparison that compared nothing would pass."""
        names = set(FIELDS)

        assert _name_drift(names, (*FIELDS, "kernel_lockdown")) == {
            "missing": {"kernel_lockdown"},
            "extra": set(),
        }
        assert _name_drift(names, FIELDS[1:]) == {
            "missing": set(),
            "extra": {FIELDS[0]},
        }

    def test_a_model_that_takes_any_name_reads_as_accepting_none_of_them(self):
        """Must-flag: the field as it was before the names were closed, a dict of text
        to text, is not read as agreeing with the register."""

        class AnyName(BaseModel):
            facts: dict[str, str] = {}

        names = _fact_names(AnyName)

        assert names == set()
        assert _name_drift(names, FIELDS) != NO_DRIFT


def _rows_that_raise_a_notice():
    return [
        row
        for row in REGISTER.rows
        if row.level is not SupportLevel.SUPPORTED and row.notify is not Notify.MATRIX
    ]


class TestEveryRowTheRegisterRaisesBuildsANotice:
    def test_the_loop_reads_every_level_the_register_raises(self):
        rows = _rows_that_raise_a_notice()

        assert len(rows) > 10
        assert {row.level for row in rows} == {
            SupportLevel.POLYFILLED,
            SupportLevel.DEGRADED,
            SupportLevel.UNSUPPORTED,
        }
        assert {row.notify for row in rows} == {Notify.START, Notify.DECISION}

    @pytest.mark.parametrize("row", _rows_that_raise_a_notice(), ids=lambda row: row.id)
    def test_the_model_holds_the_row_as_declared(self, row):
        notice = notice_of_row(row)

        assert notice.level == row.level.value
        assert notice.behavior == row.behavior.value
        assert notice.raised == row.notify.value
        assert [path.id for path in notice.paths] == list(row.paths)
        for path in notice.paths:
            declared = REGISTER.path(path.id)
            assert path.kind == declared.kind.value
            assert (path.group == "this-machine") == declared.kind.here

    def test_every_path_kind_the_register_offers_is_held(self):
        used = {
            path.kind
            for row in _rows_that_raise_a_notice()
            for path in notice_of_row(row).paths
        }

        assert used <= {kind.value for kind in PathKind}
        assert "same-os" in used and "other-host" in used


class TestAWordOutsideTheVocabularyIsRefused:
    """The must-flag side: each field refuses a word the register does not have, and
    the same record with the word put right is accepted (the control)."""

    def test_control_the_record_the_cases_change_is_accepted(self):
        assert cpu_notice().level == "unsupported"

    @pytest.mark.parametrize(
        "change",
        [
            {"level": "supported"},
            {"level": "Unsupported"},
            {"behavior": "stops"},
            {"raised": "matrix"},
            {"raised": "end"},
        ],
        ids=lambda change: "-".join(f"{k}={v}" for k, v in change.items()),
    )
    def test_the_notice_refuses_it(self, change):
        with pytest.raises(ValidationError):
            cpu_notice(**change)

    @pytest.mark.parametrize(
        "change",
        [
            {"kind": "elsewhere"},
            {"kind": "this-machine"},
            {"group": "here"},
            {"group": "this-machine", "kind": "other-host"},
            {"group": "elsewhere", "kind": "same-os"},
        ],
        ids=lambda change: "-".join(f"{k}={v}" for k, v in change.items()),
    )
    def test_the_path_refuses_it(self, change):
        record = {
            "id": "wsl2",
            "group": "this-machine",
            "kind": "wsl",
            "summary": "Install ASH inside WSL 2 and scan from there.",
            "docs": "how-to/supported-configurations.md#wsl2",
        }
        assert UpgradePathNotice(**record).kind == "wsl"

        with pytest.raises(ValidationError):
            UpgradePathNotice(**{**record, **change})
