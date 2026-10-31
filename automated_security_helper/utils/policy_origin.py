# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which findings came from a scanner only the workspace policy added.

The workspace executor marks the findings of a scanner that only
``workspace.additional_scanners`` asked for with ``properties.origin:
workspace-policy`` (and writes the same word into the finding's tags for
readers that group by tag). A project's outcome reads the *origin* alone to
decide whether such a finding counts: with ``policy_scanners_gate`` off it is
reported and excluded from the actionable count.

The constant and the one predicate live here so a reader that regrades a
finding (a report) asks the question the way the outcome does. A tag is not the
mark: scanner rule metadata and imported results files can carry any tag, so a
reader that took a tag for the mark skipped a finding the project's outcome
counted.
"""

from __future__ import annotations

from collections.abc import Mapping

#: The ``properties.origin`` value that marks a policy-origin finding.
POLICY_ORIGIN = "workspace-policy"


def is_policy_origin(properties: object) -> bool:
    """Whether *properties* (a finding's property bag) marks it policy-origin.

    *properties* is the bag as a mapping, or as a model whose extras hold the
    keys the schema does not declare (a pydantic model with extras allowed
    answers attribute access for them). Only ``origin`` decides; tags never do.
    ``None``, or a bag that holds no origin, is not policy-origin.
    """
    if properties is None:
        return False
    if isinstance(properties, Mapping):
        return properties.get("origin") == POLICY_ORIGIN
    return getattr(properties, "origin", None) == POLICY_ORIGIN
