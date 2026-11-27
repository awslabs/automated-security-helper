"""A stored suppression whose scope was kept empty stays inert after the fold.

A results file is read with the TOLERATE_STORED_CONFIG context: an entry a
config file would refuse is kept, recorded in the notes, and never applied.
The entry-level ``resource_id`` sugar is folded into ``scope.resource_id``;
when the stored scope was kept empty (``selects_nothing``), the fold must not
write into it, or the entry becomes an active scope on that resource.
"""

import pytest
from pydantic import ValidationError

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.core import (
    EMPTY_SCOPE_NOTE,
    AshSuppression,
)
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.utils.unknown_keys import TOLERATE_STORED_CONFIG

pytestmark = pytest.mark.unit

RESOURCE = "Stack/Thing/Resource"


def _finding(resource_id=RESOURCE):
    return FlatVulnerability(
        id="f1",
        title="t",
        description="d",
        severity="MEDIUM",
        scanner="cdk-nag",
        scanner_type="IAC",
        rule_id="AwsSolutions-IAM5",
        file_path="cdk.out/Stack.template.json",
        resource_id=resource_id,
        resource_type="AWS::IAM::Policy",
    )


def _entry(**extra):
    return {
        "path": "cdk.out/*.template.json",
        "rule_id": "AwsSolutions-IAM5",
        "reason": "r",
        **extra,
    }


def _stored(entry):
    """Load one suppression the way a results file's config is read."""
    notes: list = []
    config = AshConfig.model_validate(
        {
            "project_name": "stored",
            "global_settings": {"suppressions": [entry]},
        },
        context={TOLERATE_STORED_CONFIG: notes},
    )
    (loaded,) = config.global_settings.suppressions
    return loaded, notes


class TestStoredEmptyScopeStaysInert:
    def test_resource_id_with_an_empty_scope_does_not_suppress(self):
        entry = AshSuppression.model_validate(
            _entry(resource_id=RESOURCE, scope={}),
            context={TOLERATE_STORED_CONFIG: []},
        )
        assert entry.scope is not None and entry.scope.selects_nothing
        assert entry.scope.resource_id is None
        assert not entry.matches(_finding())

    def test_the_same_shape_read_through_a_stored_config_is_inert(self):
        loaded, notes = _stored(_entry(resource_id=RESOURCE, scope={}))
        assert EMPTY_SCOPE_NOTE in notes
        assert loaded.scope.selects_nothing
        assert not loaded.matches(_finding())

    def test_the_empty_scope_note_is_recorded_once_per_entry(self):
        notes: list = []
        AshSuppression.model_validate(
            _entry(resource_id=RESOURCE, scope={}),
            context={TOLERATE_STORED_CONFIG: notes},
        )
        assert notes.count(EMPTY_SCOPE_NOTE) == 1

    def test_an_empty_sugar_value_with_an_empty_scope_notes_once(self):
        notes: list = []
        entry = AshSuppression.model_validate(
            _entry(resource_id="", scope={}),
            context={TOLERATE_STORED_CONFIG: notes},
        )
        assert notes.count(EMPTY_SCOPE_NOTE) == 1
        assert not entry.matches(_finding())

    def test_the_note_is_recorded_once_through_a_stored_config(self):
        _, notes = _stored(_entry(resource_id=RESOURCE, scope={}))
        assert notes.count(EMPTY_SCOPE_NOTE) == 1


class TestControls:
    def test_a_well_formed_stored_sugar_entry_still_suppresses(self):
        loaded, notes = _stored(_entry(resource_id=RESOURCE))
        assert EMPTY_SCOPE_NOTE not in notes
        assert loaded.scope.resource_id == RESOURCE
        assert loaded.matches(_finding())
        assert not loaded.matches(_finding("Stack/Other/Resource"))

    def test_a_stored_scope_naming_another_field_still_takes_the_sugar(self):
        entry = AshSuppression.model_validate(
            _entry(resource_id=RESOURCE, scope={"resource_type": "AWS::IAM::Policy"}),
            context={TOLERATE_STORED_CONFIG: []},
        )
        assert entry.scope.resource_id == RESOURCE
        assert entry.matches(_finding())

    @pytest.mark.parametrize("scope", [{}, {"engines": {}}])
    def test_a_config_file_still_refuses_the_empty_scope_shape(self, scope):
        with pytest.raises(ValidationError) as excinfo:
            AshSuppression.model_validate(_entry(resource_id=RESOURCE, scope=scope))
        assert "selects nothing" in str(excinfo.value)
