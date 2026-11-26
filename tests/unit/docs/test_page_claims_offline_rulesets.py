# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The docs name ``--offline-rulesets`` as the option and its old spelling as deprecated.

The static freshness check validates every option a page names against the real click
tree. ``--offline-semgrep-rulesets`` is still a real spelling of that option, so the
check passes whichever one a page teaches, and only this module notices a page going back
to the deprecated name or dropping the deprecation notice.

Each test follows the pattern of test_page_claims.py in two halves: ``assert_on_page``
checks that the sentence is still on its page, and the test then probes the code that
makes it true: both spellings bind one option on ``scan`` and ``container build``, the
old spelling maps to the new one, and using it warns on stderr while the new one is
silent. A test goes red when either half moves.
"""

from __future__ import annotations

import sys
from unittest import mock

import pytest
import typer.main

from tests.unit.docs.test_page_claims import _page_text, assert_on_page

pytestmark = pytest.mark.unit

CANONICAL = "--offline-rulesets"
DEPRECATED = "--offline-semgrep-rulesets"
INDEX_PAGE = "index.md"
OFFLINE_PAGE = "how-to/run-offline.md"
MIGRATE_PAGE = "how-to/migrate-from-v2.md"
ADVANCED_PAGE = "docs/advanced-usage.md"
CLI_PAGE = "reference/cli.md"


def _option_spellings(path: tuple[str, ...]) -> list[str]:
    from automated_security_helper.cli.main import app

    command = typer.main.get_command(app)
    for name in path:
        command = command.commands[name]
    bound = [
        param.opts
        for param in command.params
        if CANONICAL in getattr(param, "opts", [])
        or DEPRECATED in getattr(param, "opts", [])
    ]
    assert len(bound) == 1, f"{' '.join(path)}: expected one option, found {bound}"
    return list(bound[0])


def _warning_for(spelling: str, capsys) -> str:
    from automated_security_helper.cli.deprecations import (
        warn_deprecated_option_spellings,
    )

    with mock.patch.object(
        sys, "argv", ["ashx", "container", "build", spelling, "p/ci"]
    ):
        warn_deprecated_option_spellings()
    return capsys.readouterr().err


def _probe_the_rename(capsys) -> None:
    from automated_security_helper.cli.deprecations import (
        DEPRECATED_OPTION_SPELLINGS,
    )

    assert DEPRECATED_OPTION_SPELLINGS[DEPRECATED] == CANONICAL
    for path in (("scan",), ("container", "build")):
        assert _option_spellings(path) == [CANONICAL, DEPRECATED]
    old = _warning_for(DEPRECATED, capsys)
    assert DEPRECATED in old and CANONICAL in old
    assert "deprecated" in old and "scheduled for removal" in old
    assert _warning_for(CANONICAL, capsys) == ""


def test_the_home_page_teaches_the_canonical_flag_and_calls_the_old_one_deprecated(
    capsys,
) -> None:
    """index.md (How do I run ASH in an offline/air-gapped environment?)."""
    assert_on_page(
        INDEX_PAGE,
        "`ashx --mode container --offline --offline-rulesets p/ci --no-run`",
    )
    assert_on_page(
        INDEX_PAGE,
        "Its old spelling, `--offline-semgrep-rulesets`, is deprecated: it still works, "
        "prints a warning on stderr, and is scheduled for removal.",
    )
    assert f"{DEPRECATED} p/ci" not in _page_text(INDEX_PAGE)
    _probe_the_rename(capsys)


def test_run_offline_names_the_canonical_flag_and_the_deprecation(capsys) -> None:
    """run-offline.md (The offline image)."""
    assert_on_page(
        OFFLINE_PAGE,
        "the opengrep rulesets named by `--offline-rulesets` (default `p/ci`), and fails",
    )
    assert_on_page(
        OFFLINE_PAGE,
        "The old spelling, `--offline-semgrep-rulesets`, is deprecated: it still works, "
        "prints a warning on stderr, and is scheduled for removal.",
    )
    _probe_the_rename(capsys)


def test_migrate_from_v2_maps_the_v2_flag_to_the_canonical_one(capsys) -> None:
    """migrate-from-v2.md (the v2 flag table)."""
    assert_on_page(
        MIGRATE_PAGE,
        "| --offline-semgrep-rulesets | `--offline-rulesets`, changed.",
    )
    assert_on_page(
        MIGRATE_PAGE,
        "The v2 spelling `--offline-semgrep-rulesets` is deprecated: it still works, "
        "prints a warning on stderr, and is scheduled for removal.",
    )
    _probe_the_rename(capsys)


def test_advanced_usage_examples_use_the_canonical_flag(capsys) -> None:
    """advanced-usage.md (Offline Mode)."""
    assert_on_page(
        ADVANCED_PAGE, "ashx container build --offline --offline-rulesets p/ci"
    )
    assert_on_page(
        ADVANCED_PAGE,
        'ashx container build --offline --offline-rulesets "p/ci p/python"',
    )
    assert_on_page(
        ADVANCED_PAGE,
        "the deprecated spelling `--offline-semgrep-rulesets` still works and warns",
    )
    assert f"container build --offline {DEPRECATED}" not in _page_text(ADVANCED_PAGE)
    _probe_the_rename(capsys)


def test_the_cli_reference_lists_the_canonical_flag_first(capsys) -> None:
    """reference/cli.md (container build and scan option tables)."""
    for anchor in ("container-build", "scan"):
        assert_on_page(
            CLI_PAGE,
            f'<a id="{anchor}--offline-rulesets"></a>`{CANONICAL}`, '
            f"`{DEPRECATED}` | text | `p/ci`",
        )
    _probe_the_rename(capsys)
