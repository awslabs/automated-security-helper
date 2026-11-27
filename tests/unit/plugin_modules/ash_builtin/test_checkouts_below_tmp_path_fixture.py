"""The checkout fixture hides the checkouts above ``tmp_path``, and the tests that need it use it.

The trust rules walk every git checkout at or above the scanned directory. A
pytest base temp inside a clone therefore puts a checkout above ``tmp_path``, and
a baseline the test places there and names as the operator's reads as the
repository's. ``checkouts_below_tmp_path`` (conftest.py) keeps only the checkouts
at or below ``tmp_path``. The first two tests show what it changes, with the walk
replaced by a fixed answer so that no ``.git`` is made above the temporary
directory. The rest keep the modules that this change touches and whose cases
depend on it using it: each module's source is parsed for the module-level
``pytestmark`` that names the fixture, so no test module is imported a second time,
and two cases show the check reading a module that names the fixture and refusing
one that does not.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

FIXTURE = "checkouts_below_tmp_path"

NEEDS_IT = (
    "test_detect_secrets_baseline_entries_are_known",
    "test_detect_secrets_baseline_links_are_judged_where_named",
    "test_detect_secrets_malformed_baseline_falls_back",
    "test_detect_secrets_operator_filters_keep_precedence",
    "test_detect_secrets_repository_baseline_is_scanned",
    "test_detect_secrets_scanner_behavior",
    "test_detect_secrets_settings_edges",
    "test_detect_secrets_tree_baseline_settings_are_not_applied",
)


def names_the_fixture_in_its_module_marks(source: str) -> bool:
    """Whether the module-level ``pytestmark`` of ``source`` holds a
    ``usefixtures`` mark that names the fixture."""
    for node in ast.parse(source).body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(
            isinstance(target, ast.Name) and target.id == "pytestmark"
            for target in node.targets
        ):
            continue
        for call in ast.walk(node.value):
            if (
                isinstance(call, ast.Call)
                and isinstance(call.func, ast.Attribute)
                and call.func.attr == "usefixtures"
                and any(
                    isinstance(argument, ast.Constant) and argument.value == FIXTURE
                    for argument in call.args
                )
            ):
                return True
    return False


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
    source = Path(__file__).with_name(f"{module_name}.py").read_text(encoding="utf-8")

    assert names_the_fixture_in_its_module_marks(source), module_name


def test_the_check_reads_a_fixture_named_among_several_marks():
    source = (
        "import pytest\n"
        "pytestmark = [\n"
        "    pytest.mark.unit,\n"
        f'    pytest.mark.usefixtures("no_tool_probes", "{FIXTURE}"),\n'
        "]\n"
    )

    assert names_the_fixture_in_its_module_marks(source)


def test_the_check_refuses_a_module_that_names_the_fixture_anywhere_else():
    source = (
        "import pytest\n"
        'pytestmark = pytest.mark.usefixtures("no_tool_probes")\n'
        f"# {FIXTURE}\n"
        f"def test_one({FIXTURE}):\n"
        "    pass\n"
    )

    assert not names_the_fixture_in_its_module_marks(source)
