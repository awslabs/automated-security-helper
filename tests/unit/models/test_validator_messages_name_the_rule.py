# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A validator's refusal states the rule, and never the value it refused.

Each message below is the one wording for its check, the same in a scan,
``ash config validate``, ``ash config lint``, ``ash merge`` and the MCP tools.
None quotes the refused value: the shared redaction (``ConfigValidator.
format_model_error``) only replaces a value it can recognize, and a value a
config file reads from the environment can be anything. An error a message is
raised in place of is not chained, so a traceback does not show it either.
Each case refuses a canary and asserts the exact message and its absence.
"""

from __future__ import annotations

import re
from typing import Annotated
from unittest.mock import patch

import pytest
from pydantic import BaseModel, ValidationError

from automated_security_helper.base import options
from automated_security_helper.config.ash_config import (
    AshConfig,
    ContentDbStalenessOverride,
)
from automated_security_helper.models.asharp_model import ReportMetadata
from automated_security_helper.models.core import AshSuppression, IgnorePathWithReason
from automated_security_helper.utils.content_databases import CONTENT_DATABASES

pytestmark = pytest.mark.unit

CANARY = "ash-canary-7f3e-0123456789"

EXPIRATION = "Invalid expiration date format. Use YYYY-MM-DD"
SYMBOL = (
    "symbol must be a dotted qualified name such as 'MyClass.my_method' "
    "(identifiers joined by '.', no spaces, wildcards or call syntax)"
)
DATETIME = "generated_at must be an ISO 8601 date and time"
DECLARED = sorted(entry.name for entry in CONTENT_DATABASES)


def _shows_the_value(text: str) -> bool:
    squeezed = re.sub(r"[\W_]", "", text).casefold()
    return re.sub(r"[\W_]", "", CANARY).casefold() in squeezed


def _refusal(build) -> dict:
    with pytest.raises(ValidationError) as caught:
        build()
    errors = caught.value.errors()
    assert len(errors) == 1, [error["loc"] for error in errors]
    return errors[0]


def _quotes_the_value(error: dict) -> bool:
    """Whether the message, or the error raised for it, holds the value. Not the
    error's ``input``: pydantic lists that apart, and every printer drops it."""
    return _shows_the_value(error["msg"]) or _shows_the_value(
        str(error["ctx"]["error"])
    )


def _assert_refused_with(error: dict, message: str) -> None:
    # Booleans, so a failure never prints the refused value.
    worded = error["msg"] == f"Value error, {message}"
    assert worded, "not the rule's wording"
    quoted = _quotes_the_value(error)
    assert not quoted, "the message quotes the refused value"
    raised = error["ctx"]["error"]
    # Not chained: no other error, whose text could quote the value, rides along.
    assert raised.__cause__ is None
    assert raised.__context__ is None or raised.__suppress_context__


@pytest.mark.parametrize(
    "build",
    [
        pytest.param(
            lambda: AshSuppression(
                rule_id="B101", path="a.py", reason="r", expiration=CANARY
            ),
            id="suppression",
        ),
        pytest.param(
            lambda: IgnorePathWithReason(
                path="vendor/**", reason="r", expiration=CANARY
            ),
            id="ignore-path",
        ),
        pytest.param(
            lambda: ContentDbStalenessOverride(
                database=DECLARED[0], policy="warn", expiration=CANARY, reason="r"
            ),
            id="content-database-override",
        ),
    ],
)
def test_an_expiration_that_is_not_a_date(build):
    _assert_refused_with(_refusal(build), EXPIRATION)


@pytest.mark.parametrize(
    "symbol",
    [f"{CANARY} with spaces", 4242],
    ids=["text", "not-text"],
)
def test_a_symbol_that_is_not_a_dotted_name(symbol):
    error = _refusal(
        lambda: AshSuppression(rule_id="B101", path="a.py", reason="r", symbol=symbol)
    )
    _assert_refused_with(error, SYMBOL)


def test_a_content_database_that_is_not_declared():
    error = _refusal(
        lambda: ContentDbStalenessOverride(
            database=CANARY, policy="warn", expiration="2099-01-01", reason="r"
        )
    )
    _assert_refused_with(
        error, f"unknown content database; declared databases: {', '.join(DECLARED)}"
    )


def test_two_overrides_for_one_content_database():
    entry = {
        "database": DECLARED[0],
        "policy": "warn",
        "expiration": "2099-01-01",
        "reason": "r",
    }
    error = _refusal(
        lambda: AshConfig.model_validate(
            {"content_db_staleness_overrides": [dict(entry), dict(entry)]}
        )
    )
    _assert_refused_with(
        error,
        "content_db_staleness_overrides entries 0 and 1 name the same content "
        "database; one named by more than one entry would be ambiguous",
    )


def test_a_generated_at_that_is_not_a_date_and_time():
    _assert_refused_with(
        _refusal(lambda: ReportMetadata(generated_at=CANARY)), DATETIME
    )


def test_an_output_format_that_is_not_one():
    error = _refusal(lambda: AshConfig.model_validate({"output_formats": [CANARY]}))
    worded = error["msg"].startswith(
        "Value error, the value is not a valid format. Valid formats are: "
    )
    assert worded, "not the rule's wording"
    quoted = _quotes_the_value(error)
    assert not quoted, "the message quotes the refused value"


class _Versions(BaseModel):
    version: Annotated[str, options.release_tag("probe.release_tag")] = "v1.0.0"
    tool_version: Annotated[
        str, options.tool_version_constraint("probe.tool_version")
    ] = ">=1.0.0"


@pytest.mark.parametrize(
    "field, warning",
    [
        (
            "version",
            (
                "Ignoring probe.release_tag: the value is not a release tag such "
                "as 'v1.2.3'. Using the pinned version instead."
            ),
        ),
        (
            "tool_version",
            (
                "Ignoring probe.tool_version: the value is not a version "
                "constraint; use PEP 440 specifiers such as '>=1.2.0,<2.0.0' or "
                "'==1.4.1'. Using the default constraint instead."
            ),
        ),
    ],
)
def test_an_option_that_is_replaced_by_its_default(field, warning):
    with patch("automated_security_helper.utils.log.ASH_LOGGER") as log:
        model = _Versions.model_validate({field: f"{CANARY} {field}"})
    # The control: the option fell back to its default.
    assert getattr(model, field) == _Versions.model_fields[field].default
    log.warning.assert_called_once_with(warning)


def test_a_detect_secrets_settings_path_that_is_not_honored(tmp_path):
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        detect_secrets_scanner as module,
    )

    source = tmp_path / "proj"
    source.mkdir()
    context = PluginContext(
        source_dir=source,
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "converted",
        config=get_default_config(),
    )
    scanner = module.DetectSecretsScanner(
        context=context, config=module.DetectSecretsScannerConfig()
    )
    scanner.config.options.scan_settings.filters_used = [
        module.DetectSecretsScanSettingsFiltersUsed(path=f"{CANARY}.filters"),
        module.DetectSecretsScanSettingsFiltersUsed(path=f"file://{CANARY}.py"),
    ]
    with patch.object(module, "ASH_LOGGER") as log:
        scanner._drop_in_tree_settings_paths()
    warnings = [str(call.args[0]) for call in log.warning.call_args_list]
    # The control: both entries were dropped, each with its warning.
    assert scanner.config.options.scan_settings.filters_used == []
    key = "scanners.detect-secrets.options.scan_settings.filters_used[].path"
    named = [warning.split(":")[0] == f"Ignoring {key}" for warning in warnings]
    assert named == [True, True], "a warning does not start with the key alone"
    quoted = any(_shows_the_value(warning) for warning in warnings)
    assert not quoted, "a warning quotes the path"
