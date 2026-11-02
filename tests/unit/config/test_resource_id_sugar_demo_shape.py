# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Entry-level ``resource_id`` is first-class sugar for ``scope.resource_id``.

The key users invented on their own is the key ASH accepts: the demo-file
shape (cdk-nag suppressions carrying a top-level ``resource_id``, one of them
``expires``) loads with zero warnings and suppresses exactly the intended
findings. The fixture here reconstructs that shape (25 entries, one
``expires``); it is pinned to the reported shape of the one-observability-demo
``.ash/.ash.yaml``, which is not in this repository.
"""

import pytest
from pydantic import ValidationError

from automated_security_helper.config.resolve_config import build_config
from automated_security_helper.models.core import (
    AshSuppression,
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
        entry = {
            "rule_id": "AwsSolutions-IAM5",
            "path": "cdk.out/*.template.json",
            "reason": f"demo suppression {index}",
            "resource_id": f"{STACK}/Construct{index}/DefaultPolicy/Resource",
        }
        if index == 0:
            entry["expires"] = "2099-12-31"
        entries.append(entry)
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
        assert len(config.global_settings.suppressions) == 26
        assert config.global_settings.suppressions[0].expiration == "2099-12-31"

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
