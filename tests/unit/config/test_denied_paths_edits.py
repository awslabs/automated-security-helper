# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What an operator's own ``denied_paths`` list does.

A list that is not one of ASH's defaults adds to the current defaults, so an
operator who denies one more field does not lift the others. With
``replace_default_denied_paths`` the list is used as written, and the default
entries it leaves out are named in a warning. Every entry, and every
``denied_value_patterns`` key, is a JSON pointer starting with ``/``: one that
is not would match nothing, so it is refused when the config is read.
"""

from __future__ import annotations

import logging
from typing import List

import pytest
from pydantic import ValidationError

from automated_security_helper.config import client_config_policy as ccp
from automated_security_helper.config.ash_config import (
    AshConfig,
    RuntimeOverridesConfig,
)
from automated_security_helper.utils.log import ASH_LOGGER


def _policy(**fields) -> RuntimeOverridesConfig:
    config = AshConfig.model_validate(
        {"global_settings": {"mcp": {"runtime_overrides": fields}}}
    )
    return ccp.policy_of(config)


@pytest.fixture
def ash_log():
    records: List[logging.LogRecord] = []

    class _Keep(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = _Keep(level=logging.WARNING)
    ASH_LOGGER.addHandler(handler)
    ccp._WARNED_REPLACEMENTS.clear()
    try:
        yield records
    finally:
        ASH_LOGGER.removeHandler(handler)
        ccp._WARNED_REPLACEMENTS.clear()


@pytest.mark.parametrize(
    "field,value",
    [
        ("denied_paths", ["fail_on_findings"]),
        ("denied_paths", ["/project_name", "scanners/*/enabled"]),
        ("denied_value_patterns", {"global_settings/suppressions": ".*"}),
    ],
)
def test_an_entry_without_a_leading_slash_is_refused(field, value) -> None:
    with pytest.raises(ValidationError) as excinfo:
        RuntimeOverridesConfig(**{field: value})
    assert "start with '/'" in str(excinfo.value)


def test_an_edited_list_adds_to_the_defaults() -> None:
    policy = _policy(denied_paths=["/project_name"])

    assert "/project_name" in policy.denied_paths
    for entry in RuntimeOverridesConfig().denied_paths:
        assert entry in policy.denied_paths


def test_replace_uses_the_list_as_written_and_names_what_it_drops(ash_log) -> None:
    policy = _policy(denied_paths=["/project_name"], replace_default_denied_paths=True)

    assert policy.denied_paths == ["/project_name"]
    (warning,) = [
        r.getMessage() for r in ash_log if "replace_default" in r.getMessage()
    ]
    assert "/fail_on_findings" in warning
    ccp.policy_of(
        AshConfig.model_validate(
            {
                "global_settings": {
                    "mcp": {
                        "runtime_overrides": {
                            "denied_paths": ["/project_name"],
                            "replace_default_denied_paths": True,
                        }
                    }
                }
            }
        )
    )
    assert len([r for r in ash_log if "replace_default" in r.getMessage()]) == 1, (
        "warned once per list"
    )


def test_effective_policy_is_idempotent() -> None:
    policy = _policy(denied_paths=["/project_name"])
    assert ccp.effective_policy(policy) is policy


def test_a_short_list_keeps_the_restrict_only_and_suppression_rules() -> None:
    """Listing one other field leaves sandbox, modules and suppressions to their rules."""
    policy = _policy(denied_paths=["/project_name"])
    assert set(ccp.exempt_paths(policy)) == set(
        ccp.RESTRICT_ONLY_PATHS + ccp.SUPPRESSION_PATHS
    )


def test_listing_suppressions_decides_them_in_denied_paths() -> None:
    policy = _policy(denied_paths=["/global_settings/suppressions"])
    exempt = ccp.exempt_paths(policy)
    assert "/global_settings/suppressions" not in exempt
    assert "/global_settings/suppressions/**" not in exempt
    assert "/global_settings/ignore_paths" in exempt
    assert "/sandbox" in exempt


def test_an_entry_above_a_field_names_it_too() -> None:
    policy = _policy(denied_paths=["/global_settings/**"])
    exempt = ccp.exempt_paths(policy)
    assert not any(path.startswith("/global_settings/") for path in exempt)
    assert "/sandbox" in exempt


def test_a_written_out_default_list_plus_one_decides_every_entry() -> None:
    """``ash config init``'s list with an entry added names all four fields itself."""
    policy = _policy(
        denied_paths=[*RuntimeOverridesConfig().denied_paths, "/project_name"]
    )
    assert ccp.exempt_paths(policy) == ()


def test_an_entry_inside_a_field_decides_the_whole_field() -> None:
    """Listing ``/sandbox/mode`` takes the sandbox out of the restrict-only rule."""
    policy = _policy(denied_paths=["/sandbox/mode"])
    exempt = ccp.exempt_paths(policy)
    assert "/sandbox" not in exempt and "/sandbox/**" not in exempt
    assert "/ash_plugin_modules" in exempt
