# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An MCP tool's failure quotes no input a pydantic error refused.

Every tool turns an unexpected error into a response through
create_error_response, and logs it; a pydantic ValidationError's own text
quotes the refused input, which can be a secret. The error here comes from a
model that does not hide its inputs, as a plugin's own model might, so the
tools' handling is tested apart from the models' setting.
"""

import asyncio
import json
import logging
import uuid

import pytest
from pydantic import BaseModel, ValidationError

from automated_security_helper.core.resource_management.error_handling import (
    create_error_response,
)
from automated_security_helper.utils.log import ASH_LOGGER

CANARY = "ash-canary-7f3e"


class _Unhidden(BaseModel):
    flag: bool


def _refused() -> ValidationError:
    try:
        _Unhidden.model_validate({"flag": CANARY})
    except ValidationError as error:
        assert CANARY in str(error), "the control: this model quotes its input"
        return error
    raise AssertionError("the canary was accepted")


@pytest.fixture
def logged():
    """Every record ASH_LOGGER emits, formatted with its traceback."""
    lines = []

    class _Collect(logging.Handler):
        def emit(self, record):
            lines.append(logging.Formatter("%(message)s").format(record))

    handler = _Collect(level=logging.DEBUG)
    level = ASH_LOGGER.level
    ASH_LOGGER.setLevel(logging.DEBUG)
    ASH_LOGGER.addHandler(handler)
    try:
        yield lines
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(level)


def test_create_error_response():
    response = create_error_response(_refused(), "get_config")
    assert CANARY not in json.dumps(response, default=str), response
    assert "flag" in response["error"]


def test_create_error_response_for_an_error_raised_from_one():
    try:
        try:
            raise _refused()
        except ValidationError as error:
            raise RuntimeError(f"could not load: {error}") from error
    except RuntimeError as wrapped:
        response = create_error_response(wrapped, "get_config")
    assert CANARY not in json.dumps(response, default=str), response


@pytest.mark.parametrize(
    "tool, patched",
    [
        ("mcp_list_active_scans", "list_active_scans"),
        ("mcp_cancel_scan", "cancel_scan"),
    ],
)
def test_a_tools_unexpected_error(monkeypatch, logged, tool, patched):
    from automated_security_helper.cli import mcp_tools

    refused = _refused()

    async def raise_it(*args, **kwargs):
        raise refused

    monkeypatch.setattr(mcp_tools, patched, raise_it)
    function = getattr(mcp_tools, tool)
    if tool == "mcp_cancel_scan":
        result = asyncio.run(function(scan_id=str(uuid.uuid4())))
    else:
        result = asyncio.run(function())
    assert result["success"] is False, result
    assert CANARY not in json.dumps(result, default=str), result
    text = "\n".join(logged)
    assert logged and CANARY not in text, text
