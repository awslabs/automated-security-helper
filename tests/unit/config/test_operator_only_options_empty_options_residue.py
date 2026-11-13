# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An options table left empty is not "the rest" of an off-host reporter section.

The operator-only options a repository file wrote are taken out of its
document, which leaves an empty ``options`` table in the reporter's section.
That table holds nothing that will not run, so the warning must not say that
the rest of the section was ignored when the file wrote nothing else.
"""

from __future__ import annotations

import contextlib
import logging
from pathlib import Path
from typing import Iterator, List, Tuple

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.operator_only_options import (
    RepositorySettings,
    _section_within,
    confine_operator_only_options,
)

pytestmark = pytest.mark.unit

SH = "aws-security-hub"


@contextlib.contextmanager
def _warnings() -> Iterator[List[str]]:
    """ASH's warnings while the block runs, as their messages."""
    from automated_security_helper.utils.log import ASH_LOGGER

    messages: List[str] = []

    class _Collect(logging.Handler):
        def emit(self, record):
            messages.append(record.getMessage())

    handler = _Collect(level=logging.WARNING)
    level = ASH_LOGGER.level
    ASH_LOGGER.setLevel(logging.WARNING)
    ASH_LOGGER.addHandler(handler)
    try:
        yield messages
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(level)


@pytest.mark.parametrize("operator_section", [None, {}], ids=["no-section", "empty"])
def test_an_empty_options_table_is_within_a_section_without_options(operator_section):
    assert _section_within({"options": {}}, operator_section) is True


@pytest.mark.parametrize(
    "section",
    [
        {"enabled": True, "options": {}},
        {"options": {"findings_scope": "a-scope"}},
        {"options": {"nested": {"key": 1}}},
    ],
    ids=["other-key", "option-value", "nested-value"],
)
def test_a_section_that_holds_a_value_the_operator_lacks_is_not_within(section):
    """The controls: anything the section holds besides empty tables is ignored."""
    assert _section_within(section, None) is False
    assert _section_within(section, {}) is False


def test_an_empty_options_table_beside_the_operators_options_is_within():
    assert _section_within({"options": {}}, {"options": {"aws_region": "x"}}) is True


def _settle(tmp_path: Path, section: dict) -> Tuple[AshConfig, List[str]]:
    """The settle step for a repository file that wrote the scope into *section*
    (what remains of its reporter section), against a trusted base with none:
    the configuration and the warnings."""
    config = AshConfig.model_validate({"reporters": {SH: section}})
    repository = RepositorySettings(trees=[])
    repository.found.append(("reporters", SH, SH, "findings_scope", "a-scope"))
    with _warnings() as messages:
        confine_operator_only_options(
            config,
            AshConfig(),
            [],
            [tmp_path / "repository.yaml"],
            operator_record=AshConfig(),
            repository=repository,
            checkout_membership=False,
            mixed_membership=False,
            given_root_membership=False,
            undecided_membership=False,
        )
    return config, messages


def test_the_warning_for_a_file_that_wrote_only_the_scope_names_no_rest(tmp_path):
    config, messages = _settle(tmp_path, {"options": {}})

    [warning] = [m for m in messages if "findings_scope" in m]
    assert f"reporters.{SH}.options.findings_scope" in warning, warning
    assert "the rest of" not in warning, warning
    assert config._off_host_sections_warned == []


def test_the_warning_for_a_file_that_also_enabled_the_reporter_names_the_rest(
    tmp_path,
):
    """The control: the section the file wrote holds more than the options."""
    config, messages = _settle(tmp_path, {"enabled": True, "options": {}})

    [warning] = [m for m in messages if "findings_scope" in m]
    assert f"and the rest of reporters.{SH}" in warning, warning
    assert config._off_host_sections_warned == [SH]
