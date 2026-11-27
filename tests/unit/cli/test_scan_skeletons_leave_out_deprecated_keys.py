"""The skeletons of the scan subjects leave out the deprecated keys.

``--generate-cli-skeleton`` prints the template a ``--cli-json-input`` document is
written from, so every key it lists reads as one to fill in. Two options of the engine
are deprecated: ``source_dir``, which the PATH argument of ``ash scan fs`` replaces, and
``scanners``, which ``--only-scanners`` and ``--add-scanners`` replace. A template that
listed them sent whoever filled it in to a key that prints a deprecation line, so the
two subjects leave them out. A document that names one is still read, as it was.

What is pinned here:

* every option of the engine whose help says it is deprecated is out of both skeletons,
  and ``scan_group.DEPRECATED_KEYS`` is the table of the ones a subject takes, so an
  option that is deprecated later and not added to the table fails a row;
* a document made by filling in the skeleton of either subject hands the engine no
  deprecated option and prints no deprecation line;
* a document that names a deprecated key still reaches the engine, and ``source_dir``
  still prints its line;
* the form with no subject, which is deprecated as a whole, keeps the template it had;
* the help of ``--generate-cli-skeleton`` says what the template leaves out, on the
  commands that leave something out and on no other.

The engine is replaced by a stand-in that records what it was handed, so no row scans
anything.
"""

from __future__ import annotations

import json

import pytest
import typer.main
from typer.testing import CliRunner

from automated_security_helper.cli import scan_group
from automated_security_helper.cli.main import app

pytestmark = pytest.mark.unit


def _invoke(args: list[str], **kwargs):
    return CliRunner().invoke(app, args, prog_name="ash", **kwargs)


def _deprecation_lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.startswith("Deprecated:")]


@pytest.fixture(autouse=True)
def _clear_ash_env(monkeypatch):
    """A variable of the host would name a directory, a selection or a file for a row
    that names none."""
    for name in (
        "ASH_SOURCE_DIR",
        "ASH_SCANNERS",
        "ASH_OUTPUT_DIR",
        "ASH_WORKSPACE",
        "ASH_WORKSPACE_CONFIG",
    ):
        monkeypatch.delenv(name, raising=False)


class _EngineStub:
    """Stands in for the engine behind the subjects: records what it was handed."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    def __call__(self, *args, **kwargs):
        self.calls.append(kwargs)


@pytest.fixture
def engine(monkeypatch):
    stub = _EngineStub()
    monkeypatch.setattr(scan_group, "run_ash_scan_cli_command", stub)
    return stub


def _command(subject: str | None):
    """The click command of ``ash scan <subject>``, or the one the form with no subject
    runs, which takes every option of the engine."""
    group = typer.main.get_command(app).commands["scan"]
    return group.legacy_command() if subject is None else group.commands[subject]


def _skeleton(subject: str | None) -> dict:
    """The parsed ``--generate-cli-skeleton`` output of ``ash scan [subject]``."""
    words = [] if subject is None else [subject]
    result = _invoke(["scan", *words, "--generate-cli-skeleton"])
    assert result.exit_code == 0, result.output
    return json.loads(result.stdout)


def _deprecated_in_the_engine() -> set[str]:
    """The options of the engine whose help says they are deprecated."""
    return {
        param.name
        for param in _command(None).params
        if param.expose_value and "Deprecated" in (getattr(param, "help", None) or "")
    }


def _plain(value):
    return list(value) if isinstance(value, (list, tuple)) else value


# --------------------------------------------------------------------------- #
# The skeletons
# --------------------------------------------------------------------------- #


def test_the_table_of_deprecated_keys_is_the_deprecated_options_a_subject_takes():
    taken = {
        param.name
        for subject in ("fs", "workspace")
        for param in _command(subject).params
    }
    deprecated = _deprecated_in_the_engine()

    assert deprecated & taken == set(scan_group.DEPRECATED_KEYS)
    # `--workspace` is deprecated too, and neither subject takes it by that name: `fs`
    # has no workspace option, and `workspace` takes the file as its FILE argument.
    assert deprecated - taken == {"workspace"}


@pytest.mark.parametrize(
    ("subject", "named_by"), [("fs", "path"), ("workspace", "file")]
)
def test_a_subject_skeleton_lists_no_deprecated_key(subject, named_by):
    skeleton = _skeleton(subject)
    deprecated = _deprecated_in_the_engine()

    assert deprecated, "no option says it is deprecated, so there is nothing to compare"
    assert deprecated.isdisjoint(skeleton), sorted(deprecated & set(skeleton))
    # What replaces them is listed, so the template still has a key for each thing.
    assert {named_by, "only_scanners", "add_scanners"} <= set(skeleton)


def test_the_form_with_no_subject_keeps_the_template_it_had():
    skeleton = _skeleton(None)

    assert _deprecated_in_the_engine() <= set(skeleton)


# --------------------------------------------------------------------------- #
# A document made from a skeleton, and one that still names a deprecated key
# --------------------------------------------------------------------------- #

#: What a reader types into the keys of a skeleton. A key the skeleton lists that is not
#: here keeps the value the skeleton gave it. The deprecated keys are here too, so a
#: skeleton that listed one would have it filled in, and the row below would see it.
FILLED_IN = {
    "source_dir": "src",
    "scanners": ["bandit"],
    "only_scanners": ["bandit"],
    "output_dir": "out",
}


@pytest.mark.parametrize(
    ("subject", "named", "reaches_the_engine_as"),
    [
        pytest.param("fs", {"path": "src"}, "source_dir", id="fs"),
        pytest.param(
            "workspace", {"file": "dev.code-workspace"}, "workspace", id="workspace"
        ),
    ],
)
def test_a_document_filled_in_from_the_skeleton_uses_no_deprecated_option(
    engine, tmp_path, subject, named, reaches_the_engine_as
):
    filled = {**FILLED_IN, **named}
    skeleton = _skeleton(subject)
    document = tmp_path / "scan.json"
    document.write_text(
        json.dumps({key: filled.get(key, value) for key, value in skeleton.items()}),
        encoding="utf-8",
    )

    result = _invoke(["scan", subject, "--cli-json-input", str(document)])

    assert result.exit_code == 0, result.output
    assert _deprecation_lines(result.output) == [], result.output
    (call,) = engine.calls
    # The document was read: what it filled in reached the engine.
    assert call[reaches_the_engine_as] == next(iter(named.values()))
    assert _plain(call["only_scanners"]) == ["bandit"]
    assert call["output_dir"] == "out"
    # The engine prints its own line for `--scanners` when it is given any.
    assert not call["scanners"]


@pytest.mark.parametrize(
    ("subject", "document", "reaches", "prints"),
    [
        pytest.param(
            "fs", {"source_dir": "svc"}, {"source_dir": "svc"}, 1, id="fs-source_dir"
        ),
        pytest.param(
            "fs", {"--source-dir": "svc"}, {"source_dir": "svc"}, 1, id="fs-flag-key"
        ),
        pytest.param(
            "fs",
            {"scanners": ["bandit"]},
            {"scanners": ["bandit"]},
            None,
            id="fs-scanners",
        ),
        pytest.param(
            "workspace",
            {"file": "dev.code-workspace", "scanners": ["bandit"]},
            {"workspace": "dev.code-workspace", "scanners": ["bandit"]},
            None,
            id="workspace-scanners",
        ),
    ],
)
def test_a_document_may_still_name_a_deprecated_key(
    engine, tmp_path, subject, document, reaches, prints
):
    """``prints`` is the number of lines the subject prints for the key, or None where
    the line is the engine's, which the stand-in replaces."""
    path = tmp_path / "scan.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    result = _invoke(["scan", subject, "--cli-json-input", str(path)])

    assert result.exit_code == 0, result.output
    (call,) = engine.calls
    assert {key: _plain(call[key]) for key in reaches} == reaches
    if prints is not None:
        assert len(_deprecation_lines(result.output)) == prints, result.output


# --------------------------------------------------------------------------- #
# The help of the option that prints the skeleton
# --------------------------------------------------------------------------- #


def _skeleton_option_help(command) -> str:
    (option,) = [
        param for param in command.params if param.name == "generate_cli_skeleton"
    ]
    return option.help


@pytest.mark.parametrize("subject", ["fs", "workspace"])
def test_a_subject_says_what_its_template_leaves_out(subject):
    help_text = _skeleton_option_help(_command(subject))

    assert "Deprecated parameters are left out of the template" in help_text
    assert "a document that names one is still read" in help_text


def test_a_command_that_leaves_nothing_out_does_not_say_so():
    results = typer.main.get_command(app).commands["results"]

    for command in (_command(None), results.commands["report"]):
        assert "left out" not in _skeleton_option_help(command)
