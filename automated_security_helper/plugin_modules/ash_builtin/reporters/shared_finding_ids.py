# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The former home of ``shared_ids_by_position`` and ``flat_describes_result``.

The helper now lives in ``automated_security_helper.utils.shared_finding_ids``,
where ``utils/sarif_utils.py`` imports it at load time: a utility module no longer
reaches into the reporters package to find it. This module re-exports the same
objects so the GitLab SAST and OCSF reporters, and their tests, keep their import
spelling; new code imports from ``utils``.
"""

from automated_security_helper.utils.shared_finding_ids import (
    flat_describes_result,
    shared_ids_by_position,
)

__all__ = ["shared_ids_by_position", "flat_describes_result"]
