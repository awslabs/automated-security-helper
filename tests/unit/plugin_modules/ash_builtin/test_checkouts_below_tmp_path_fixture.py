"""The checkout fixture hides the checkouts above ``tmp_path``, and the tests that need it use it.

The trust rules walk every git checkout at or above the scanned directory. A
pytest base temp inside a clone therefore puts a checkout above ``tmp_path``, and
a baseline the test places there and names as the operator's reads as the
repository's. ``checkouts_below_tmp_path`` (conftest.py) keeps only the checkouts
at or below ``tmp_path``. The first two tests show what it changes, with the walk
replaced by a fixed answer so that no ``.git`` is made above the temporary
directory; the third keeps the seven modules whose cases depend on it using it.
"""

from __future__ import annotations

import importlib

import pytest

NEEDS_IT = (
    "test_detect_secrets_baseline_entries_are_known",
    "test_detect_secrets_baseline_links_are_judged_where_named",
    "test_detect_secrets_malformed_baseline_falls_back",
    "test_detect_secrets_operator_filters_keep_precedence",
    "test_detect_secrets_scanner_behavior",
    "test_detect_secrets_settings_edges",
    "test_detect_secrets_tree_baseline_settings_are_not_applied",
)


@pytest.fixture
def one_checkout_above_and_one_below(monkeypatch, tmp_path):
    """The walk's answer for a clone that holds the temporary directory and a
    checkout the test made inside it."""
    from automated_security_helper.config import path_trust

    (tmp_path / "repo" / "src").mkdir(parents=True)
    checkouts = [tmp_path.parent, tmp_path / "repo"]
    monkeypatch.setattr(
        path_trust, "_checkouts_holding", lambda scan_root: list(checkouts)
    )
    return checkouts


def test_without_the_fixture_both_checkouts_are_seen(
    one_checkout_above_and_one_below, tmp_path
):
    from automated_security_helper.config import path_trust

    assert (
        path_trust._checkouts_holding(tmp_path / "repo" / "src")
        == one_checkout_above_and_one_below
    )


def test_the_fixture_hides_the_checkout_above_the_temporary_directory(
    one_checkout_above_and_one_below, checkouts_below_tmp_path, tmp_path
):
    from automated_security_helper.config import path_trust

    assert path_trust._checkouts_holding(tmp_path / "repo" / "src") == [
        tmp_path / "repo"
    ]


@pytest.mark.parametrize("module_name", NEEDS_IT)
def test_the_modules_whose_cases_need_it_use_it(module_name):
    module = importlib.import_module(
        f"tests.unit.plugin_modules.ash_builtin.{module_name}"
    )
    marks = (
        module.pytestmark
        if isinstance(module.pytestmark, list)
        else [module.pytestmark]
    )
    used = {
        argument
        for mark in marks
        if mark.name == "usefixtures"
        for argument in mark.args
    }
    assert "checkouts_below_tmp_path" in used, used
