# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The settle helper's trailing flags bind only by keyword.

The two confinement entry points and the membership sentence helpers carry
this guard with their own cells
(test_a_deleted_working_directory_fails_closed_everywhere.py). This file
pins the one remaining keyword-only signature of the two option-confinement
modules, ``_set_by_override``: its trailing parameters are judgment inputs
(the section kind, the environment values), and a positional call written
against an older or imagined signature must fail with a TypeError instead of
binding one of them silently. Removing the ``*`` from the signature turns
this cell red.
"""

from __future__ import annotations

import pytest


def test_set_by_override_takes_its_kind_only_by_keyword():
    from automated_security_helper.config.operator_only_options import (
        _set_by_override,
    )

    # The match pins the TypeError to the signature's refusal: without it,
    # a body that raised TypeError on its own would mask a dropped star.
    with pytest.raises(TypeError, match="positional argument"):
        _set_by_override({}, "section", "option", None, "reporters")
