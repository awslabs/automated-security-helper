# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An unidentified caller's session config is refused with a type of its own.

``materialize_session_config`` refuses ``UNIDENTIFIED_SESSION_ID``, a caller the
server could not identify and that owns no session workspace. It used to raise a
bare ``RuntimeError``, the type the workspace tools map to an invalid-config
refusal (exit 3), so a caller that named a per-call ``profile`` without a
server-issued session was told its config was wrong. The refusal now carries its
own type. It is still a ``RuntimeError``, so every handler that caught the bare
one still does, and a tool can answer it as the session-identity refusal.
"""

from __future__ import annotations

import pytest

from automated_security_helper.cli.mcp.profile_registry import (
    materialize_session_binding,
    materialize_session_config,
)
from automated_security_helper.cli.mcp.session_identity import (
    UNIDENTIFIED_SESSION_ID,
)
from automated_security_helper.config.ash_config import AshConfig

pytestmark = pytest.mark.unit


def test_the_refusal_has_its_own_type() -> None:
    """Named without importing it, so the test reads the type the registry raises."""
    with pytest.raises(RuntimeError) as refused:
        materialize_session_config(UNIDENTIFIED_SESSION_ID, AshConfig())

    assert type(refused.value).__name__ == "SessionIdentityRequiredError", refused.value


def test_the_type_is_a_runtime_error_the_registry_exports() -> None:
    from automated_security_helper.cli.mcp.profile_registry import (
        SessionIdentityRequiredError,
    )

    assert issubclass(SessionIdentityRequiredError, RuntimeError)
    with pytest.raises(SessionIdentityRequiredError):
        materialize_session_binding(UNIDENTIFIED_SESSION_ID, AshConfig(), None)
