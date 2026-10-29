# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``_resolve_forward_refs`` imports ``config.ash_config`` before taking its lock.

The last line of ``config/ash_config.py`` calls ``_resolve_forward_refs``. With
the import inside the lock, a thread importing that module held its import lock
and then asked for ``_forward_refs_lock``, while a thread that first used the
model here held ``_forward_refs_lock`` and asked for the import lock: a
deadlock. The import now runs first, under the import system's own locking.

Measured by reading the function's source rather than by racing two threads: a
race that reproduces the deadlock hangs the run that measures it.
"""

from __future__ import annotations

import inspect

import pytest

from automated_security_helper.models import asharp_model

pytestmark = pytest.mark.unit


def test_the_import_precedes_the_lock():
    source = inspect.getsource(asharp_model._resolve_forward_refs)
    import_at = source.index(
        "from automated_security_helper.config.ash_config import AshConfig"
    )
    lock_at = source.index("with _forward_refs_lock:")

    assert import_at < lock_at, source


def test_resolution_still_binds_the_config_class():
    asharp_model._resolve_forward_refs()

    assert asharp_model._forward_refs_resolved is True
    assert getattr(asharp_model, "AshConfig", None) is not None
