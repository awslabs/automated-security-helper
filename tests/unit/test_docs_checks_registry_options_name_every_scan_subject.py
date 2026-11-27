"""The docs check reads the names a page gives ``ash scan <subject>``, for every subject.

``scripts/docs_checks.py`` holds the value of ``--scanners``, ``--exclude-scanners`` and
``--output-formats`` to ASH's registries, for the command that owns the option:
``REGISTRY_OPTIONS`` is keyed by that command's path. ``ash scan`` has a command for
each subject, ``fs`` and ``workspace``, and a subject with no row there has every value
a page gives it passed unchecked, with no error to say so.

The subjects and their options are read here from the real command tree, so a subject
the CLI gains fails the first test until the table names it. The pages below run the
check itself against both subjects, with the fs rows as the control that a refused
value is reported where the table has a row.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
import typer.main

from automated_security_helper.cli.main import app

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
FENCE = "```"
#: The options whose values are names ASH keeps a registry of, as the table lists them.
REGISTRY_OPTION_NAMES = (
    "--scanners",
    "--exclude-scanners",
    "--only-scanners",
    "--add-scanners",
    "--output-formats",
)
#: What each subject takes where its command line names the thing to scan.
TARGETS = {"fs": ".", "workspace": "w.code-workspace"}


def _load_docs_checks():
    name = "_ash_docs_checks"
    if name in sys.modules:
        return sys.modules[name]
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    spec = importlib.util.spec_from_file_location(
        name, REPO_ROOT / "scripts" / "docs_checks.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


dc = _load_docs_checks()


def _subjects() -> dict:
    """The subjects of ``scan`` with their commands, from the real command tree."""
    return typer.main.get_command(app).commands["scan"].commands


def _first_names(command) -> set[str]:
    """The first name of each option a click command declares: the key the table uses."""
    return {
        param.opts[0] for param in command.params if param.param_type_name == "option"
    }


def _findings(tmp_path: Path, line: str) -> list[str]:
    """What the CLI check says about one ``ash`` line in a bash block of a page."""
    root = tmp_path / "repo"
    (root / "docs").mkdir(parents=True)
    (root / dc.PRE_COMMIT_HOOKS).write_text(
        (REPO_ROOT / dc.PRE_COMMIT_HOOKS).read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    page = root / "docs" / "page.md"
    page.write_text(f"# Values\n\n{FENCE}bash\n{line}\n{FENCE}\n", encoding="utf-8")
    return [str(finding) for finding in dc.check_cli([page], root)]


def test_every_scan_subject_has_a_row_for_each_registry_option_it_takes():
    wanted = {
        (("ash", "scan", name), option)
        for name, command in _subjects().items()
        for option in REGISTRY_OPTION_NAMES
        if option in _first_names(command)
    }

    # Held to literals too, so a read of the tree that came back empty cannot pass:
    # fs takes the three, and workspace takes them as well.
    assert {
        (("ash", "scan", subject), option)
        for subject in ("fs", "workspace")
        for option in REGISTRY_OPTION_NAMES
    } <= wanted
    assert wanted <= set(dc.REGISTRY_OPTIONS), sorted(wanted - set(dc.REGISTRY_OPTIONS))


@pytest.mark.parametrize("option", REGISTRY_OPTION_NAMES)
def test_a_subject_holds_its_values_to_the_registry_the_group_does(option):
    kind = dc.REGISTRY_OPTIONS[(("ash", "scan"), option)]

    for subject in _subjects():
        row = dc.REGISTRY_OPTIONS.get((("ash", "scan", subject), option))
        assert row in (None, kind), (subject, option, row)


@pytest.mark.parametrize("subject", sorted(TARGETS))
@pytest.mark.parametrize(
    ("words", "reported"),
    [
        pytest.param(
            "--scanners not-a-scanner",
            "ASH has no scanner named 'not-a-scanner'",
            id="a-scanner",
        ),
        pytest.param(
            "--exclude-scanners bandit,not-a-scanner",
            "ASH has no scanner named 'not-a-scanner'",
            id="a-scanner-in-a-list",
        ),
        pytest.param(
            "--output-formats sarf",
            "'sarf' is not an output format",
            id="an-output-format",
        ),
        pytest.param(
            "--only-scanners not-a-scanner",
            "ASH has no scanner named 'not-a-scanner'",
            id="an-only-scanner",
        ),
        pytest.param(
            "--add-scanners bandit,not-a-scanner",
            "ASH has no scanner named 'not-a-scanner'",
            id="an-added-scanner-in-a-list",
        ),
    ],
)
def test_a_name_the_registry_does_not_have_is_reported_under_every_subject(
    tmp_path, subject, words, reported
):
    findings = _findings(tmp_path, f"ash scan {subject} {TARGETS[subject]} {words}")

    assert any(reported in finding for finding in findings), findings


@pytest.mark.parametrize("subject", sorted(TARGETS))
def test_names_the_registry_has_pass_under_every_subject(tmp_path, subject):
    findings = _findings(
        tmp_path,
        f"ash scan {subject} {TARGETS[subject]} --scanners bandit "
        "--exclude-scanners bandit --output-formats sarif,junitxml",
    )
    assert findings == []

    findings = _findings(
        tmp_path,
        f"ash scan {subject} {TARGETS[subject]} --only-scanners bandit,detect-secrets",
    )
    assert findings == []

    findings = _findings(
        tmp_path, f"ash scan {subject} {TARGETS[subject]} --add-scanners bandit"
    )
    assert findings == []


@pytest.mark.parametrize(
    ("line", "reported"),
    [
        pytest.param(
            "ash results report --format not-a-reporter",
            "ASH has no reporter named 'not-a-reporter'",
            id="results-report-format",
        ),
        pytest.param(
            "ash results merge --results a --output-formats sarf",
            "'sarf' is not an output format",
            id="results-merge-output-formats",
        ),
    ],
)
def test_a_name_the_registry_does_not_have_is_reported_under_results(
    tmp_path, line, reported
):
    """``results report`` and ``results merge`` run the functions ``report`` and
    ``merge`` run, so their values are held to the same registries."""
    findings = _findings(tmp_path, line)

    assert any(reported in finding for finding in findings), findings


def test_names_the_registry_has_pass_under_results(tmp_path):
    assert _findings(tmp_path, "ash results report --format sarif") == []
    assert (
        _findings(
            tmp_path, "ash results merge --results a --output-formats sarif,junitxml"
        )
        == []
    )
