# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A validator's own message names the field and the rule, never the value.

``hide_input_in_errors`` keeps pydantic's ``input_value=`` out of an error's text,
but a validator that puts the value into its own ``ValueError`` puts it in the
message, which is in ``str(e)``, ``repr(e)`` and ``errors()[].msg``. So is a library
error a validator lets through, such as ``datetime.fromisoformat``'s. A config
value can be a secret read from the environment, and the message reaches the
console, ``ash.log`` and MCP responses. The same holds for the warning a validator
logs when it replaces a value with its default.

Each case reads the value from the environment, as ``!ENV`` in a config file
does, and checks it is in none of the error's text, its ``errors()`` messages and
the log, while the field is still named.
"""

from __future__ import annotations

import logging
import traceback
from pathlib import Path
from typing import Iterator, List

import pytest
from pydantic import ValidationError

CANARY = "ash-canary-env-91d2"
ENV_NAME = "ASH_CANARY_VALUE"


@pytest.fixture
def ash_log() -> Iterator[List[str]]:
    """Each record logged to ASH's logger, with its traceback."""
    records: List[str] = []

    class _Recorder(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            text = record.getMessage()
            if record.exc_info:
                text += "".join(traceback.format_exception(*record.exc_info))
            records.append(text)
            return True

    logger = logging.getLogger("ash")
    recorder = _Recorder()
    logger.addFilter(recorder)
    yield records
    logger.removeFilter(recorder)


@pytest.fixture
def canary_env(monkeypatch) -> None:
    monkeypatch.setenv(ENV_NAME, CANARY)


def _chain(error: BaseException) -> List[BaseException]:
    seen: List[BaseException] = []
    current: BaseException | None = error
    while current is not None and all(current is not e for e in seen):
        seen.append(current)
        current = current.__cause__ or current.__context__
    return seen


def _assert_named_without_the_value(
    error: BaseException, log: List[str], field: str
) -> None:
    for link in _chain(error):
        assert CANARY not in str(link), (type(link).__name__, str(link))
        assert CANARY not in repr(link), repr(link)
        assert all(CANARY not in str(arg) for arg in link.args), link.args
        if isinstance(link, ValidationError):
            messages = [item["msg"] for item in link.errors()]
            assert all(CANARY not in message for message in messages), messages
    assert CANARY not in "".join(traceback.format_exception(error))
    assert [record for record in log if CANARY in record] == []
    assert field in str(error), str(error)


def _resolve(tmp_path: Path, document: str):
    from automated_security_helper.config.resolve_config import resolve_config

    tree = tmp_path / "tree"
    (tree / ".ash").mkdir(parents=True)
    (tree / ".ash" / ".ash.yaml").write_text(document, encoding="utf-8")
    return resolve_config(source_dir=tree)


_ENV = f"!ENV ${{{ENV_NAME}}}"

#: A config document whose value a validator refuses, read from the environment,
#: and the field the refusal names.
_SUPPRESSION = "global_settings:\n  suppressions:\n    - path: app.py\n"

_REFUSED = {
    "suppression-expiration": (
        _SUPPRESSION
        + f"      rule_id: B101\n      reason: r\n      expiration: {_ENV}\n",
        "expiration",
    ),
    "suppression-symbol": (
        _SUPPRESSION + f"      rule_id: B101\n      reason: r\n      symbol: {_ENV}\n",
        "symbol",
    ),
    "denied-paths": (
        (
            "global_settings:\n  mcp:\n    runtime_overrides:\n"
            f"      denied_paths:\n        - {_ENV}\n"
        ),
        "denied_paths",
    ),
    "content-db-database": (
        (
            "content_db_staleness_overrides:\n"
            f"  - database: {_ENV}\n    policy: warn\n    expiration: '2099-01-01'\n"
            "    reason: r\n"
        ),
        "database",
    ),
    "content-db-expiration": (
        (
            "content_db_staleness_overrides:\n"
            "  - database: trivy-db\n    policy: warn\n"
            f"    expiration: {_ENV}\n    reason: r\n"
        ),
        "expiration",
    ),
}


@pytest.mark.parametrize("case", sorted(_REFUSED))
@pytest.mark.usefixtures("canary_env")
def test_a_refusal_names_the_field_and_not_the_value(tmp_path, ash_log, case):
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    document, field = _REFUSED[case]

    with pytest.raises(ASHConfigValidationError) as excinfo:
        _resolve(tmp_path, document)

    _assert_named_without_the_value(excinfo.value, ash_log, field)


def test_a_denied_value_patterns_key_is_not_quoted(ash_log):
    """A mapping key cannot be read from the environment, but a refused key is the
    file's text all the same, so the refusal counts it and does not quote it."""
    from automated_security_helper.config.ash_config import AshConfig

    with pytest.raises(ValidationError) as excinfo:
        AshConfig.model_validate(
            {
                "global_settings": {
                    "mcp": {
                        "runtime_overrides": {
                            "enabled": True,
                            "denied_value_patterns": {CANARY: ".*"},
                        }
                    }
                }
            }
        )

    _assert_named_without_the_value(excinfo.value, ash_log, "denied_value_patterns")


def test_two_overrides_of_one_database_are_named_by_position(tmp_path, ash_log):
    """The database is one of the declared names, and the refusal says which
    entries collide rather than which database."""
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    entry = (
        "  - database: grype-db\n    policy: warn\n    expiration: '2099-01-01'\n"
        "    reason: r\n"
    )
    with pytest.raises(ASHConfigValidationError) as excinfo:
        _resolve(tmp_path, "content_db_staleness_overrides:\n" + entry + entry)

    message = str(excinfo.value)
    assert "content_db_staleness_overrides" in message, message
    assert "entries 0 and 1" in message, message
    assert "grype-db" not in message, message


def test_a_results_file_timestamp_is_not_quoted(ash_log):
    """``generated_at`` is read from a results file; ``datetime.fromisoformat``'s
    own message would quote it."""
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    with pytest.raises(ValidationError) as excinfo:
        AshAggregatedResults.model_validate({"metadata": {"generated_at": CANARY}})

    _assert_named_without_the_value(excinfo.value, ash_log, "generated_at")


#: A plugin option a validator replaces with its default, with one warning, read
#: from the environment, and the key the warning names.
_REPLACED = {
    "tool-version": (
        f"scanners:\n  bandit:\n    options:\n      tool_version: {_ENV}\n",
        "scanners.bandit.options.tool_version",
    ),
    "release-tag": (
        f"scanners:\n  opengrep:\n    options:\n      version: {_ENV}\n",
        "scanners.opengrep.options.version",
    ),
    "report-extension": (
        f"reporters:\n  markdown:\n    extension: {_ENV}/x\n",
        "reporters.markdown.extension",
    ),
}


@pytest.mark.parametrize("case", sorted(_REPLACED))
@pytest.mark.usefixtures("canary_env")
def test_a_replaced_option_s_warning_names_the_key_and_not_the_value(
    tmp_path, ash_log, case
):
    from automated_security_helper.base.options import (
        reset_refused_tool_version_warnings,
    )

    reset_refused_tool_version_warnings()
    document, key = _REPLACED[case]

    _resolve(tmp_path, document)

    warned = [record for record in ash_log if key in record]
    assert warned, ash_log
    assert [record for record in ash_log if CANARY in record] == []


@pytest.mark.usefixtures("canary_env")
def test_a_report_file_name_s_warning_names_the_key_and_not_the_value(ash_log):
    from automated_security_helper.base.options import (
        reset_refused_tool_version_warnings,
    )
    from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
        BedrockSummaryReporterConfig,
    )

    reset_refused_tool_version_warnings()
    key = "reporters.bedrock-summary-reporter.options.output_file"

    BedrockSummaryReporterConfig.model_validate(
        {"options": {"output_file": f"../{CANARY}"}}
    )

    assert [record for record in ash_log if key in record], ash_log
    assert [record for record in ash_log if CANARY in record] == []
