# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The aggregated results model's forward reference is imported before the lock.

The last line of ``config/ash_config.py`` calls the model's resolver. With the
import inside the lock, a thread importing that module held its import lock and
then asked for the resolver's lock, while a thread that first used the model held
the resolver's lock and asked for the import lock: a deadlock. The import now runs
first, under the import system's own locking, in the shared
``base.forward_refs.OnceOnlyResolver`` both models call.

Measured by reading the resolver's source rather than by racing two threads: a
race that reproduces the deadlock hangs the run that measures it.
"""

from __future__ import annotations

import inspect

import pytest

from automated_security_helper.base.forward_refs import OnceOnlyResolver
from automated_security_helper.models import asharp_model

pytestmark = pytest.mark.unit


def test_the_import_precedes_the_lock():
    source = inspect.getsource(OnceOnlyResolver.resolve)
    import_at = source.index("target = import_target()")
    lock_at = source.index("with self._lock:")

    assert import_at < lock_at, source


def test_resolution_still_binds_the_config_class():
    asharp_model._resolve_forward_refs()

    assert asharp_model._forward_refs.resolved is True
    assert getattr(asharp_model, "AshConfig", None) is not None
