# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Entry-level ``resource_id`` is first-class sugar for ``scope.resource_id``.

The key users invented on their own is the key ASH accepts: the demo-file
shape loads with zero warnings and suppresses exactly the intended findings.
The fixture here reconstructs that shape, pinned to the real
one-observability-demo ``.ash/.ash.yaml`` (not in this repository): 25 cdk-nag
suppressions carrying a top-level ``resource_id`` (keys
``rule_id``/``path``/``resource_id``/``reason``), and the file's ONE
``expires`` sitting on a dependency-advisory entry WITHOUT ``resource_id``
(keys ``rule_id``/``path``/``reason``/``expires``), never on a
resource-scoped entry.
"""

import pytest
from pydantic import ValidationError

from automated_security_helper.config.resolve_config import build_config
from automated_security_helper.models.core import (
    AshSuppression,
    EMPTY_SCOPE_NOTE,
    RESOURCE_ID_CONFLICT_NOTE,
)
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.utils.suppression_matcher import (
    should_suppress_finding,
)
from automated_security_helper.utils.unknown_keys import TOLERATE_STORED_CONFIG

pytestmark = pytest.mark.unit

STACK = "ObservabilityDemoStack"


def _demo_entries():
    entries = []
    for index in range(25):
        entries.append(
            {
                "rule_id": "AwsSolutions-IAM5",
                "path": "cdk.out/*.template.json",
                "reason": f"demo suppression {index}",
                "resource_id": f"{STACK}/Construct{index}/DefaultPolicy/Resource",
            }
        )
    # The real file's one `expires` sits on a dependency-advisory rule for a
    # lockfile, WITHOUT a resource_id, not on a resource-scoped entry.
    entries.append(
        {
            "rule_id": "GHSA-demo-advisory",
            "path": "package-lock.json",
            "reason": "accepted dependency advisory",
            "expires": "2099-12-31",
        }
    )
    # The control: a resource_id that matches no finding, so it must stay
    # un-applied while its siblings apply.
    entries.append(
        {
            "rule_id": "AwsSolutions-IAM5",
            "path": "cdk.out/*.template.json",
            "reason": "control: matches nothing",
            "resource_id": f"{STACK}/NoSuchConstruct/Resource",
        }
    )
    return entries


def _finding(index=3):
    return FlatVulnerability(
        id=f"f{index}",
        title="t",
        description="d",
        severity="MEDIUM",
        scanner="cdk-nag",
        scanner_type="IAC",
        rule_id="AwsSolutions-IAM5",
        file_path="cdk.out/ObservabilityDemoStack.template.json",
        resource_id=f"{STACK}/Construct{index}/DefaultPolicy/Resource",
        resource_type="AWS::IAM::Policy",
    )


class TestSugarFolds:
    def test_sugar_folds_into_scope(self):
        entry = AshSuppression.model_validate(
            {"path": "a", "reason": "r", "resource_id": "Stack/Thing"}
        )
        assert entry.scope is not None
        assert entry.scope.resource_id == "Stack/Thing"

    def test_an_equal_duplicate_is_accepted(self):
        entry = AshSuppression.model_validate(
            {
                "path": "a",
                "reason": "r",
                "resource_id": "Stack/Thing",
                "scope": {"resource_id": "Stack/Thing"},
            }
        )
        assert entry.scope.resource_id == "Stack/Thing"

    def test_disagreeing_values_are_refused_with_keep_one(self):
        with pytest.raises(ValidationError) as excinfo:
            AshSuppression.model_validate(
                {
                    "path": "a",
                    "reason": "r",
                    "resource_id": "Stack/One",
                    "scope": {"resource_id": "Stack/Two"},
                }
            )
        assert "resource_id and scope.resource_id disagree; keep one" in str(
            excinfo.value
        )

    def test_an_empty_sugar_value_with_a_scope_block_is_refused(self):
        # The fold wrote "" into an already-validated scope by plain attribute
        # assignment, which skips SuppressionScope's validators
        # (validate_assignment is not set), so the entry loaded silently inert.
        with pytest.raises(ValidationError) as excinfo:
            AshSuppression.model_validate(
                {
                    "path": "cdk.out/*.template.json",
                    "reason": "r",
                    "resource_id": "",
                    "scope": {"resource_type": "AWS::IAM::Policy"},
                }
            )
        # The refusal names the sugar field the author wrote.
        assert "an empty resource_id selects nothing" in str(excinfo.value)

    def test_an_empty_sugar_value_without_a_scope_is_still_refused(self):
        # The control: this config-load refusal predates the fix.
        with pytest.raises(ValidationError) as excinfo:
            AshSuppression.model_validate({"path": "a", "reason": "r", "resource_id": ""})
        assert "selects nothing" in str(excinfo.value)

    def test_a_stored_empty_sugar_value_without_a_scope_still_loads(self):
        # The fold built the scope with a bare constructor call, which carries
        # no context, so the tolerance was lost and the whole stored results
        # file was refused.
        notes: list = []
        entry = AshSuppression.model_validate(
            {
                "path": "cdk.out/*.template.json",
                "rule_id": "AwsSolutions-IAM5",
                "reason": "r",
                "resource_id": "",
            },
            context={TOLERATE_STORED_CONFIG: notes},
        )
        assert EMPTY_SCOPE_NOTE in notes
        assert entry.scope is not None and entry.scope.selects_nothing
        assert not entry.matches(_finding())

    def test_a_stored_empty_sugar_value_with_a_scope_block_is_noted_and_inert(self):
        notes: list = []
        entry = AshSuppression.model_validate(
            {
                "path": "cdk.out/*.template.json",
                "rule_id": "AwsSolutions-IAM5",
                "reason": "r",
                "resource_id": "",
                "scope": {"resource_type": "AWS::IAM::Policy"},
            },
            context={TOLERATE_STORED_CONFIG: notes},
        )
        assert EMPTY_SCOPE_NOTE in notes
        assert entry.scope.selects_nothing
        assert not entry.matches(_finding())

    def test_a_valid_sugar_value_still_folds_and_matches(self):
        # The control the fix must not narrow: the demo shape keeps working.
        entry = AshSuppression.model_validate(
            {
                "path": "cdk.out/*.template.json",
                "rule_id": "AwsSolutions-IAM5",
                "reason": "r",
                "resource_id": f"{STACK}/Construct3/DefaultPolicy/Resource",
            }
        )
        assert entry.scope.resource_id == f"{STACK}/Construct3/DefaultPolicy/Resource"
        assert entry.matches(_finding(3))

    def test_a_tolerated_disagreement_never_applies(self):
        notes: list = []
        entry = AshSuppression.model_validate(
            {
                "path": "cdk.out/*.template.json",
                "reason": "r",
                "rule_id": "AwsSolutions-IAM5",
                "resource_id": f"{STACK}/Construct3/DefaultPolicy/Resource",
                "scope": {"resource_id": "Stack/Other"},
            },
            context={TOLERATE_STORED_CONFIG: notes},
        )
        assert RESOURCE_ID_CONFLICT_NOTE in notes
        assert not entry.matches(_finding())


class TestDemoShapeEndToEnd:
    def test_the_demo_shape_loads_with_zero_warnings(self):
        config = build_config(
            {
                "project_name": "demo-shape",
                "global_settings": {"suppressions": _demo_entries()},
            }
        )
        assert config._resolution_warnings == []
        suppressions = config.global_settings.suppressions
        assert len(suppressions) == 27
        # The one expiring entry is the dependency rule with no resource_id,
        # as in the real file.
        expiring = [s for s in suppressions if s.expiration is not None]
        assert len(expiring) == 1
        assert expiring[0].expiration == "2099-12-31"
        assert expiring[0].rule_id == "GHSA-demo-advisory"
        assert expiring[0].scope is None

    def test_expires_on_a_sugar_entry_also_loads(self):
        """NOT the demo shape (the real file's one expires entry carries no
        resource_id); this fixture's own extra coverage of the expires alias
        combined with the sugar key on one entry."""
        config = build_config(
            {
                "project_name": "demo-shape",
                "global_settings": {
                    "suppressions": [
                        {
                            "rule_id": "AwsSolutions-IAM5",
                            "path": "cdk.out/*.template.json",
                            "reason": "r",
                            "resource_id": (
                                f"{STACK}/Construct0/DefaultPolicy/Resource"
                            ),
                            "expires": "2099-12-31",
                        }
                    ]
                },
            }
        )
        assert config._resolution_warnings == []
        (entry,) = config.global_settings.suppressions
        assert entry.expiration == "2099-12-31"
        assert entry.scope is not None and entry.scope.resource_id

    def test_it_suppresses_exactly_the_intended_findings(self):
        config = build_config(
            {
                "project_name": "demo-shape",
                "global_settings": {"suppressions": _demo_entries()},
            }
        )
        suppressions = config.global_settings.suppressions
        suppressed, matched = should_suppress_finding(_finding(3), suppressions)
        assert suppressed is True
        assert matched.reason == "demo suppression 3"
        # The control entry applies to nothing: a finding its resource_id does
        # not name is only matched by its own entry, never the control.
        control = [s for s in suppressions if "control" in s.reason]
        assert len(control) == 1
        assert not control[0].matches(_finding(3))

    def test_a_finding_outside_every_resource_id_is_not_suppressed(self):
        config = build_config(
            {
                "project_name": "demo-shape",
                "global_settings": {"suppressions": _demo_entries()},
            }
        )
        stranger = _finding(3)
        stranger.resource_id = f"{STACK}/UnlistedConstruct/Resource"
        suppressed, _ = should_suppress_finding(
            stranger, config.global_settings.suppressions
        )
        assert suppressed is False
