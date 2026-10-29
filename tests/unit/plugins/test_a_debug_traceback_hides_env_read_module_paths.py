# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The DEBUG traceback and its neighbors hide an env-read module's every form.

A crashing env-read module's traceback quotes the module's dotted path in its
message and the path form (modules/zq.../crashy/__init__.py) in its frames and
__file__, so redacting the dotted value alone leaves the path form in the
DEBUG traceback line. The loader widens the needles with the "/" and "\\"
path forms of an env-read dotted entry, in the one place both arms, the
WARNING line and the DEBUG line draw from. The merge redacts with the shards'
merged config, so the operator config's env values join it: the operator's
module entry, and any other value the operator's config read that an import
error can quote. A literal module's traceback keeps its name and its error's
words: redaction costs a readable failure nothing.

Every ash record is caught by a level-1 sink, so the DEBUG line is read
wherever the command sends it; each command also runs at DEBUG so the line
exists (the control in each cell).
"""

from __future__ import annotations

import logging
import sys

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.utils.log import ASH_LOGGER
from tests.unit.cli.test_merge import build_shards, write_shards

pytestmark = pytest.mark.unit

VARIABLE = "ASH_ZQDBGMOD"
LINE = "failure traceback"
CRASH = 'raise RuntimeError("cannot initialise " + __name__ + " from " + __file__)\n'


class _Sink(logging.Handler):
    def __init__(self):
        super().__init__(level=1)
        self.messages: list = []

    def emit(self, record):
        self.messages.append(record.getMessage())


@pytest.fixture
def records():
    sink = _Sink()
    level = ASH_LOGGER.level
    ASH_LOGGER.addHandler(sink)
    ASH_LOGGER.setLevel(1)
    yield sink.messages
    ASH_LOGGER.removeHandler(sink)
    ASH_LOGGER.setLevel(level)


@pytest.fixture
def modules(tmp_path, monkeypatch):
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    for name in (
        "ASH_PLUGIN_MODULES",
        "ASH_SOURCE_DIR",
        "ASH_OUTPUT_DIR",
        "ASH_CONFIG",
        "ASH_WORKSPACE",
    ):
        monkeypatch.delenv(name, raising=False)
    root = tmp_path / "modules"
    root.mkdir()
    monkeypatch.syspath_prepend(str(root))
    yield root
    for name in [m for m in sys.modules if m.startswith("zqdbg")]:
        sys.modules.pop(name, None)


def _crashing(root, dotted):
    parts = dotted.split(".")
    for depth in range(1, len(parts) + 1):
        package = root.joinpath(*parts[:depth])
        package.mkdir(exist_ok=True)
        init = package / "__init__.py"
        init.write_text(CRASH if depth == len(parts) else "", encoding="utf-8")


def _env_config(path, monkeypatch, value):
    monkeypatch.setenv(VARIABLE, value)
    path.write_text(
        f"project_name: api\nash_plugin_modules:\n  - !ENV ${{{VARIABLE}}}\n",
        encoding="utf-8",
    )
    return path


def _scan(tmp_path, monkeypatch):
    source = tmp_path / "src"
    source.mkdir(exist_ok=True)
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.chdir(source)
    return source, [
        "scan",
        "--mode",
        "local",
        "--no-progress",
        "--log-level",
        "DEBUG",
        "--source-dir",
        str(source),
        "--output-dir",
        str(tmp_path / "out"),
    ]


def _merge_args(tmp_path, config):
    args = ["merge"]
    for path in write_shards(tmp_path / "artifacts", build_shards(2)):
        args += ["--results", path]
    return args + [
        "--output-dir",
        str(tmp_path / "merged"),
        "--no-color",
        "--config",
        str(config),
        "--log-level",
        "DEBUG",
    ]


def _value_free(value, result, records):
    """No form of *value* in the DEBUG traceback, any other record, or the
    output; the traceback line itself was logged (the control)."""
    joined = " ".join(records)
    if LINE not in joined:
        raise RuntimeError(
            ("control: the DEBUG traceback was not logged", result.output[-1500:])
        )
    if result.exit_code != 3:
        raise RuntimeError(("control: the command was not refused", result.exit_code))
    tracebacks = "\n".join(m for m in records if LINE in m)
    others = "\n".join(m for m in records if LINE not in m)
    for form in (value, value.replace(".", "/")):
        shown = {
            "debug_traceback": form in tracebacks,
            "other_records": form in others,
            "output": form in result.output,
        }
        assert not any(shown.values()), (form, shown, tracebacks[-1200:])


def test_a_scans_debug_traceback_hides_a_one_part_value(
    tmp_path, monkeypatch, modules, records
):
    value = "zqdbgone_ash_plugins"
    _crashing(modules, value)
    source, args = _scan(tmp_path, monkeypatch)
    _env_config(source / ".ash.yaml", monkeypatch, value)
    result = CliRunner().invoke(app, args)
    _value_free(value, result, records)


def test_a_scans_debug_traceback_hides_a_dotted_value_in_both_forms(
    tmp_path, monkeypatch, modules, records
):
    value = "zqdbgtwo_ash_plugins.crashy"
    _crashing(modules, value)
    source, args = _scan(tmp_path, monkeypatch)
    _env_config(source / ".ash.yaml", monkeypatch, value)
    result = CliRunner().invoke(app, args)
    _value_free(value, result, records)


def test_a_merges_debug_traceback_hides_the_operators_value(
    tmp_path, monkeypatch, modules, records
):
    value = "zqdbgmerge_ash_plugins"
    _crashing(modules, value)
    config = _env_config(tmp_path / "operator.yaml", monkeypatch, value)
    collector = tmp_path / "collector"
    collector.mkdir()
    monkeypatch.chdir(collector)
    result = CliRunner().invoke(app, _merge_args(tmp_path, config))
    _value_free(value, result, records)


def test_a_merge_hides_another_operator_value_a_literal_modules_error_quotes(
    tmp_path, monkeypatch, modules, records
):
    """The merge redacts with the merged config, which was the shards' alone:
    a literally named operator module whose ImportError quotes a value the
    operator's config read with !ENV elsewhere printed that value in the
    WARNING line, the DEBUG traceback and the output."""
    secret = "zqdbgmergesecret-5531"
    monkeypatch.setenv("ASH_ZQDBGREASON", secret)
    name = "zqdbgmergelit_ash_plugins"
    (modules / name).mkdir()
    (modules / name / "__init__.py").write_text(
        'import os\nraise ImportError("cannot use " + os.environ["ASH_ZQDBGREASON"])\n',
        encoding="utf-8",
    )
    config = tmp_path / "operator.yaml"
    config.write_text(
        f"project_name: api\nash_plugin_modules:\n  - {name}\n"
        "global_settings:\n  ignore_paths:\n    - path: 'vendor'\n"
        "      reason: !ENV ${ASH_ZQDBGREASON}\n",
        encoding="utf-8",
    )
    collector = tmp_path / "collector"
    collector.mkdir()
    monkeypatch.chdir(collector)
    result = CliRunner().invoke(app, _merge_args(tmp_path, config))
    _value_free(secret, result, records)


def test_plugin_lists_debug_traceback_hides_the_value(
    tmp_path, monkeypatch, modules, records
):
    value = "zqdbglist_ash_plugins"
    _crashing(modules, value)
    config = _env_config(tmp_path / "operator.yaml", monkeypatch, value)
    project = tmp_path / "proj"
    project.mkdir()
    monkeypatch.chdir(project)
    result = CliRunner().invoke(
        app, ["plugin", "list", "--config", str(config), "--debug"]
    )
    _value_free(value, result, records)


#: Imports cleanly; reading its declarations raises, quoting __file__, so the
#: register-stage traceback holds the module's path form.
REGISTER_CRASH = (
    "def __getattr__(attribute):\n    raise RuntimeError('cannot read ' + __file__)\n"
)


def _register_crashing(root, dotted):
    parts = dotted.split(".")
    for depth in range(1, len(parts) + 1):
        package = root.joinpath(*parts[:depth])
        package.mkdir(exist_ok=True)
        init = package / "__init__.py"
        init.write_text(REGISTER_CRASH if depth == len(parts) else "", encoding="utf-8")


def test_a_scans_registration_traceback_hides_a_dotted_value_in_both_forms(
    tmp_path, monkeypatch, modules, records
):
    """The register arm's traceback line draws from the same widened values
    as the import arm's: a module that imports but fails reading its
    declarations quotes __file__, the path form of the dotted entry."""
    value = "zqdbgreg_ash_plugins.decl"
    _register_crashing(modules, value)
    source, args = _scan(tmp_path, monkeypatch)
    _env_config(source / ".ash.yaml", monkeypatch, value)
    result = CliRunner().invoke(app, args)
    _value_free(value, result, records)


def test_a_merges_registration_traceback_hides_the_operators_value(
    tmp_path, monkeypatch, modules, records
):
    value = "zqdbgregm_ash_plugins.decl"
    _register_crashing(modules, value)
    config = _env_config(tmp_path / "operator.yaml", monkeypatch, value)
    collector = tmp_path / "collector"
    collector.mkdir()
    monkeypatch.chdir(collector)
    result = CliRunner().invoke(app, _merge_args(tmp_path, config))
    _value_free(value, result, records)


def test_a_literal_modules_debug_traceback_keeps_its_name(
    tmp_path, monkeypatch, modules, records
):
    name = "zqdbglit_ash_plugins"
    _crashing(modules, name)
    source, args = _scan(tmp_path, monkeypatch)
    (source / ".ash.yaml").write_text(
        f"project_name: api\nash_plugin_modules:\n  - {name}\n", encoding="utf-8"
    )
    result = CliRunner().invoke(app, args)
    tracebacks = [m for m in records if LINE in m]
    if not tracebacks:
        raise RuntimeError(
            ("control: the DEBUG traceback was not logged", result.output[-1500:])
        )
    assert any(name in m for m in tracebacks), tracebacks
    assert any("cannot initialise " + name in m for m in tracebacks), tracebacks


#: One environment value that splits into two module names. Neither piece is
#: the whole value, so a needle set holding only the value misses both: the
#: traceback's "No module named" line and its frames quote each piece.
PIECE_A = "zqdbgpaira_ash_plugins"
PIECE_B = "zqdbgpairb_ash_plugins"
PAIR = f"{PIECE_A},{PIECE_B}"


def _pieces_free(result, records):
    """No piece of the pair, in either form, in the DEBUG traceback, any
    other record, or the output; the traceback line was logged and the
    command was refused (the controls)."""
    joined = " ".join(records)
    if LINE not in joined:
        raise RuntimeError(
            ("control: the DEBUG traceback was not logged", result.output[-1500:])
        )
    if result.exit_code != 3:
        raise RuntimeError(("control: the command was not refused", result.exit_code))
    tracebacks = "\n".join(m for m in records if LINE in m)
    others = "\n".join(m for m in records if LINE not in m)
    for piece in (PIECE_A, PIECE_B):
        for form in (piece, piece.replace(".", "/")):
            shown = {
                "debug_traceback": form in tracebacks,
                "other_records": form in others,
                "output": form in result.output,
            }
            assert not any(shown.values()), (form, shown, tracebacks[-1200:])


def test_a_scans_debug_traceback_hides_each_piece_of_a_multi_piece_value(
    tmp_path, monkeypatch, modules, records
):
    """The whole value never appears in a traceback -- only its comma-split
    pieces do, one per failed import -- so each masked module's own path has
    to be a needle, not just the value it came from."""
    for piece in (PIECE_A, PIECE_B):
        _crashing(modules, piece)
    source, args = _scan(tmp_path, monkeypatch)
    _env_config(source / ".ash.yaml", monkeypatch, PAIR)
    result = CliRunner().invoke(app, args)
    _pieces_free(result, records)


def test_plugin_lists_debug_traceback_hides_each_piece(
    tmp_path, monkeypatch, modules, records
):
    for piece in (PIECE_A, PIECE_B):
        _crashing(modules, piece)
    config = _env_config(tmp_path / "operator.yaml", monkeypatch, PAIR)
    project = tmp_path / "proj"
    project.mkdir()
    monkeypatch.chdir(project)
    result = CliRunner().invoke(
        app, ["plugin", "list", "--config", str(config), "--debug"]
    )
    _pieces_free(result, records)


def test_plugin_lists_non_debug_lines_name_no_piece(
    tmp_path, monkeypatch, modules, records
):
    """The console table, INFO and WARNING lines name a split entry's pieces
    by their markers, never by value: the CLI's split renumbers the list, and
    the reindex right after it is what keeps the second piece's marker on its
    entry. Pinned apart from the DEBUG cells so a reindex regression shows on
    its own, without the traceback redaction in the frame. No ``--debug``:
    the console would print the DEBUG traceback itself, and this cell's
    surfaces are the ones every run prints."""
    for piece in (PIECE_A, PIECE_B):
        _crashing(modules, piece)
    config = _env_config(tmp_path / "operator.yaml", monkeypatch, PAIR)
    project = tmp_path / "proj"
    project.mkdir()
    monkeypatch.chdir(project)
    result = CliRunner().invoke(app, ["plugin", "list", "--config", str(config)])
    if result.exit_code != 3:
        raise RuntimeError(("control: the listing was not refused", result.exit_code))
    others = "\n".join(m for m in records if LINE not in m)
    for piece in (PIECE_A, PIECE_B):
        shown = {
            "other_records": piece in others,
            "output": piece in result.output,
        }
        assert not any(shown.values()), (piece, shown)


def test_a_literal_pairs_debug_traceback_keeps_both_names(
    tmp_path, monkeypatch, modules, records
):
    """The control: a comma-joined LITERAL entry's pieces are the file's own
    text, so the traceback keeps both names and their errors' words."""
    for piece in (PIECE_A, PIECE_B):
        _crashing(modules, piece)
    source, args = _scan(tmp_path, monkeypatch)
    (source / ".ash.yaml").write_text(
        f"project_name: api\nash_plugin_modules:\n  - {PAIR}\n", encoding="utf-8"
    )
    result = CliRunner().invoke(app, args)
    tracebacks = [m for m in records if LINE in m]
    if not tracebacks:
        raise RuntimeError(
            ("control: the DEBUG traceback was not logged", result.output[-1500:])
        )
    for piece in (PIECE_A, PIECE_B):
        assert any(piece in m for m in tracebacks), (piece, tracebacks)
