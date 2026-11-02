# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The reason client rules are unreadable quotes no value of the operator's config.

``session_client_rules`` put the raw text of the trusted-config load error into
``rules.unreadable``, and that reason is returned to a remote MCP client with
the refusal. A pydantic validation error's own text quotes the refused input,
which for the server's default config is a value of the operator's
``ASH_CONFIG`` file. The reason is now the described error, as every other
error text the tools return.
"""

from __future__ import annotations

import pytest
from pydantic import BaseModel, ConfigDict, ValidationError

from automated_security_helper.cli.mcp.profile_registry import (
    clear_all_session_state,
    clear_profile_registry,
    session_client_rules,
)
from automated_security_helper.config import client_config_policy

pytestmark = pytest.mark.unit

AN_OPERATORS_VALUE = "operator-only-value-quoted-by-pydantic"


@pytest.fixture(autouse=True)
def _no_binding():
    clear_profile_registry()
    clear_all_session_state()
    yield
    clear_profile_registry()
    clear_all_session_state()


class _AConfigQuotingItsInput(BaseModel):
    """A stand-in config model whose own error text quotes the refused input.

    ``AshConfig`` hides its inputs (``hide_input_in_errors=True``), so an error
    from it quotes nothing wherever it is shown, and a test built on it would
    prove nothing about the described reason. The input stays in ``errors()``
    either way, which is what ``error_text`` reads.
    """

    model_config = ConfigDict(hide_input_in_errors=False)

    global_settings: dict


def _a_validation_error_quoting(value: str) -> ValidationError:
    try:
        _AConfigQuotingItsInput.model_validate({"global_settings": value})
    except ValidationError as exc:
        assert value in str(exc), "the stand-in error does not quote its input"
        assert value in str(exc.errors()), "the stand-in's errors() lose the input"
        return exc
    raise AssertionError("the stand-in accepted a string for global_settings")


def test_the_unreadable_reason_leaves_the_refused_input_out(monkeypatch) -> None:
    error = _a_validation_error_quoting(AN_OPERATORS_VALUE)

    def cannot_load(repository=None):
        raise error

    monkeypatch.setattr(client_config_policy, "trusted_default_config", cannot_load)

    rules = session_client_rules("remote-session")

    assert rules.unreadable is not None
    assert "ValidationError" in rules.unreadable
    assert AN_OPERATORS_VALUE not in rules.unreadable, rules.unreadable
    assert rules.session_id == "remote-session"
