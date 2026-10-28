# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""nbconvert runs outside the scanned tree, on a copy, with an exporter ASH chooses.

Three nbconvert behaviors make the notebook and the directory nbconvert runs in matter.
``NbConvertApp.init_syspath`` puts the working directory first on ``sys.path``,
``TemplateExporter.extra_template_basedirs`` defaults to it, and
``ScriptExporter.from_notebook_node`` imports the exporter class a notebook names in
``metadata.language_info.nbconvert_exporter``. The converter therefore runs nbconvert in
a staging directory holding only the copied notebook, removes ``nbconvert_exporter``
from that copy, and picks the exporter itself from the notebook's language.

nbconvert also reads its own arguments as patterns: each notebook argument is expanded
with ``glob.glob`` and the output name goes through ``str.format``. The copy is staged
under a fixed name, so a notebook called ``[x].ipynb`` or ``{a,b}.ipynb`` converts like
any other, and the converted file is named after the original.

These tests observe what the converter hands nbconvert, on both of the routes it can
take: ``uv tool run`` (``use_uv_tool``, the default) and the direct fallback, which
runs ``jupyter-nbconvert`` by the absolute path ASH resolved for it. Real nbconvert is
exercised in ``tests/integration/converters/test_nbconvert_runs_outside_tree.py``.

The process boundary is replaced without touching the standard library's
``subprocess`` module: the converter module's own ``subprocess`` name is pointed at a
namespace whose ``run`` is the stand-in, and the uv runner is replaced through
``get_uv_tool_runner``. On the uv route that ``run`` raises, so a failure there cannot
fall back to whatever jupyter the host has. The converter is constructed before either
is in place, so its own tool probes run against the real environment.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import tempfile
import types
from pathlib import Path

import pytest

from automated_security_helper.core.phases.convert_phase import _input_record_fields
from automated_security_helper.interactions.run_ash_scan import incomplete_converters
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ConverterStatusInfo,
)
from automated_security_helper.plugin_modules.ash_builtin.converters import (
    jupyter_converter,
)
from automated_security_helper.plugin_modules.ash_builtin.converters.jupyter_converter import (
    JupyterConverter,
    JupyterConverterConfig,
)
from automated_security_helper.utils import subprocess_utils, uv_tool_runner
from automated_security_helper.utils.normalizers import get_normalized_filename
from tests.unit.converters.nbconvert_stand_in import (
    accept_stand_in_nbconvert,
    expand,
    notebook_patterns,
    run_like_nbconvert,
)

PROBE_EXPORTER = "ashprobe_exporter.ProbeExporter"
NBCONVERT = "jupyter-nbconvert"
WINDOWS = sys.platform == "win32"


def notebook(language: str | None, exporter: str | None, code: str = "x = 1\n"):
    language_info: dict = {"file_extension": ".py"}
    if language is not None:
        language_info["name"] = language
    if exporter is not None:
        language_info["nbconvert_exporter"] = exporter
    return {
        "cells": [
            {
                "cell_type": "code",
                "metadata": {},
                "execution_count": None,
                "outputs": [],
                "source": [code],
            }
        ],
        "metadata": {"language_info": language_info},
        "nbformat": 4,
        "nbformat_minor": 5,
    }


def as_nbformat_writes(nb: dict) -> bytes:
    """The bytes nbformat writes: one-space indent, non-ASCII kept, trailing newline.

    Default ``json.dumps`` output would survive a parse-and-dump round trip unchanged,
    so a test written with it could not tell a copied notebook from a re-serialized
    one.
    """
    return (json.dumps(nb, indent=1, ensure_ascii=False) + "\n").encode("utf-8")


def fake_executable(directory: Path, name: str) -> Path:
    """A file ASH's lookup accepts as ``name``. Never run: ``spawn_run`` is replaced."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / (f"{name}.exe" if WINDOWS else name)
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    return path


class Observed:
    """What nbconvert was handed, recorded at the boundary and asserted afterwards.

    Nothing is asserted inside the stand-ins: convert() catches every exception a
    conversion raises, so an assertion there would be recorded as a failed input and
    the test would see that instead.
    """

    def __init__(self):
        self.calls: list[dict] = []
        self.result = run_like_nbconvert

    def record(self, argv: list[str], cwd) -> subprocess.CompletedProcess:
        (pattern,) = notebook_patterns(argv)
        staged = [Path(p) for p in expand(pattern)]
        self.calls.append(
            {
                "argv": list(argv),
                "cwd": None if cwd is None else Path(cwd),
                "notebook": staged[0] if staged else None,
                "staged_bytes": staged[0].read_bytes() if staged else None,
                "beside": sorted(os.listdir(staged[0].parent)) if staged else None,
            }
        )
        return self.result(list(argv))


def direct_route_run(observed: Observed):
    def run(argv, *args, **kwargs):
        return observed.record(argv, kwargs.get("cwd"))

    return run


def refuse_direct_route(argv, *args, **kwargs):
    raise AssertionError(f"the direct route ran {argv!r} on the uv route")


def replace_subprocess(monkeypatch, run) -> None:
    monkeypatch.setattr(
        jupyter_converter,
        "subprocess",
        types.SimpleNamespace(
            run=run,
            CompletedProcess=subprocess.CompletedProcess,
            CalledProcessError=subprocess.CalledProcessError,
            TimeoutExpired=subprocess.TimeoutExpired,
            SubprocessError=subprocess.SubprocessError,
        ),
    )
    # The converter starts nbconvert through spawn_run under a sandbox, so a
    # scanner sandbox can confine it, and through run_ended_with_the_server
    # otherwise (jupyter_converter._run_nbconvert); both are this double.
    monkeypatch.setattr(jupyter_converter, "spawn_run", run)
    monkeypatch.setattr(jupyter_converter, "run_ended_with_the_server", run)


@pytest.fixture(autouse=True)
def hermetic_lookups(monkeypatch, tmp_path):
    """Lookups see the PATH each test sets and nothing else.

    find_executable caches by name, and it also searches ASH's bin directory and
    /usr/local/bin whatever PATH says; either could hold a real jupyter.
    """
    monkeypatch.setattr(
        subprocess_utils, "path_independent_dirs", lambda: [tmp_path / "ash-bin"]
    )
    subprocess_utils.clear_find_executable_cache()
    yield
    subprocess_utils.clear_find_executable_cache()


@pytest.fixture
def ash_warnings():
    messages: list[str] = []

    class _Collector(logging.Handler):
        def emit(self, record):
            messages.append(record.getMessage())

    handler = _Collector(level=logging.WARNING)
    logger = logging.getLogger("ash")
    logger.addHandler(handler)
    try:
        yield messages
    finally:
        logger.removeHandler(handler)


@pytest.fixture
def tree(test_plugin_context):
    source = Path(test_plugin_context.source_dir)
    source.mkdir(parents=True, exist_ok=True)
    return source


@pytest.fixture
def outside(tmp_path) -> Path:
    """A directory outside the scanned tree, standing in for an install location."""
    return tmp_path / "installed"


@pytest.fixture
def make_converter(test_plugin_context):
    def make() -> JupyterConverter:
        return JupyterConverter(
            context=test_plugin_context, config=JupyterConverterConfig()
        )

    return make


@pytest.fixture
def direct(make_converter, monkeypatch, outside):
    """A converter on the direct route, with jupyter-nbconvert installed outside."""
    converter = make_converter()
    converter.use_uv_tool = False
    observed = Observed()
    jupyter = fake_executable(outside / "bin", NBCONVERT)
    monkeypatch.setenv("PATH", str(jupyter.parent))
    # A conversion runs a jupyter-nbconvert only once verify_pre_installed_tool
    # says its nbconvert satisfies the requirement, and the fake belongs to no
    # nbconvert distribution; these tests are about what the verified copy is
    # handed, so the verification accepts it. The lookup's refusals still hold.
    accept_stand_in_nbconvert(monkeypatch)
    replace_subprocess(monkeypatch, direct_route_run(observed))
    return converter, observed, jupyter


@pytest.fixture(params=["uv", "direct"])
def route(request, make_converter, monkeypatch, outside):
    """A converter, built first, then the route it takes to nbconvert replaced."""
    if request.param == "direct":
        converter, observed, jupyter = request.getfixturevalue("direct")
        return converter, observed, jupyter

    converter = make_converter()
    converter.use_uv_tool = True
    observed = Observed()

    class Runner:
        def is_uv_available(self):
            return True

        def run_tool(self, **kwargs):
            return observed.record(
                ["jupyter", "nbconvert", *kwargs["args"]], kwargs.get("cwd")
            )

    monkeypatch.setattr(uv_tool_runner, "get_uv_tool_runner", lambda: Runner())
    # No jupyter to fall back to, and a run that raises if one were found anyway.
    empty = outside / "empty-bin"
    empty.mkdir(parents=True)
    monkeypatch.setenv("PATH", str(empty))
    replace_subprocess(monkeypatch, refuse_direct_route)
    return converter, observed, None


def convert_one(converter, notebook_path: Path, monkeypatch) -> list[Path]:
    monkeypatch.setattr(
        f"{jupyter_converter.__name__}.scan_set", lambda **kw: [str(notebook_path)]
    )
    return converter.convert()


def failed(converter) -> list[dict]:
    """Each failed input's path and reason. The record carries more (kind,
    accepted, accepted_reason, accepted_by), which these tests do not assert."""
    return [
        {"path": record.path, "reason": record.reason}
        for record in converter.failed_inputs
    ]


def gate(converter) -> list[tuple[str, str]]:
    """What the completeness gate says about a results row built from ``converter``,
    as (name, reason); the row's third field, ``kinds``, is not asserted here."""
    row = ConverterStatusInfo(**_input_record_fields(converter))
    return [
        (listed.name, listed.reason)
        for listed in incomplete_converters(
            AshAggregatedResults(converter_results={"jupyter": row})
        )
    ]


@pytest.mark.parametrize(
    "language, expected_exporter",
    [("python", "python"), (None, "python"), ("R", "script")],
)
def test_nbconvert_runs_beside_a_copy_with_an_exporter_ash_chose(
    language, expected_exporter, route, tree, monkeypatch
):
    converter, observed, jupyter = route
    (tree / "nb.ipynb").write_bytes(
        as_nbformat_writes(notebook(language, PROBE_EXPORTER))
    )
    # Run from inside the tree, as `cd repo && ash scan` does, so a route that
    # inherited ASH's working directory would run nbconvert in the tree.
    monkeypatch.chdir(tree)

    (converted,) = convert_one(converter, tree / "nb.ipynb", monkeypatch)

    (call,) = observed.calls
    assert call["cwd"] is not None, "nbconvert inherited ASH's working directory"
    assert not call["cwd"].resolve().is_relative_to(tree.resolve())
    assert call["cwd"] == call["notebook"].parent
    assert call["beside"] == ["notebook.ipynb"], "the directory holds only the copy"
    assert not call["cwd"].exists(), "the staging directory was left behind"
    argv = call["argv"]
    assert argv[argv.index("--to") + 1] == expected_exporter
    staged = json.loads(call["staged_bytes"])
    assert "nbconvert_exporter" not in staged["metadata"]["language_info"]
    assert staged["cells"] == notebook(language, None)["cells"]
    assert converted == converter.results_dir / "nb__ipynb-converted.py"
    assert converted.read_text() == "x = 1\n"
    if jupyter is not None:
        assert argv[0] == str(jupyter), "the direct route ran nbconvert by name"
    assert failed(converter) == []


def test_a_notebook_without_an_exporter_is_copied_byte_for_byte(
    route, tree, monkeypatch
):
    converter, observed, _ = route
    original = as_nbformat_writes(notebook("python", None, code="print('café')\n"))
    (tree / "nb.ipynb").write_bytes(original)

    (converted,) = convert_one(converter, tree / "nb.ipynb", monkeypatch)

    (call,) = observed.calls
    assert call["notebook"] != tree / "nb.ipynb", "nbconvert was given the tree path"
    assert call["staged_bytes"] == original
    assert converted.read_text(encoding="utf-8") == "print('café')\n"


PATTERN_NAMES = [
    "[x].ipynb",
    "{a,b}.ipynb",
    pytest.param(
        "*.ipynb",
        marks=pytest.mark.skipif(WINDOWS, reason="'*' is not a Windows filename"),
    ),
    pytest.param(
        "?.ipynb",
        marks=pytest.mark.skipif(WINDOWS, reason="'?' is not a Windows filename"),
    ),
]


@pytest.mark.parametrize("name", PATTERN_NAMES)
def test_a_notebook_named_like_a_pattern_converts_under_its_own_name(
    name, route, tree, monkeypatch
):
    """nbconvert globs its notebook argument and formats its output name.

    ``[x].ipynb`` as a pattern matches ``x.ipynb`` and not itself, ``{a,b}`` breaks
    ``str.format``, and ``*`` and ``?`` match whatever else is beside them. The
    ``x.ipynb`` in the tree is there for a converter that handed nbconvert the
    original path: its glob would convert that notebook instead.
    """
    converter, observed, _ = route
    (tree / name).write_bytes(as_nbformat_writes(notebook("python", None, "y = 2\n")))
    (tree / "x.ipynb").write_bytes(as_nbformat_writes(notebook("python", None)))
    monkeypatch.chdir(tree)

    (converted,) = convert_one(converter, tree / name, monkeypatch)

    (call,) = observed.calls
    assert call["notebook"].name == "notebook.ipynb"
    assert converted.read_text() == "y = 2\n"
    expected = get_normalized_filename(name).replace(".ipynb", "") + "-converted.py"
    assert converted == converter.results_dir / expected
    assert failed(converter) == []


def test_a_staging_directory_whose_path_is_a_pattern_still_converts(
    route, tree, tmp_path, monkeypatch
):
    """The staging directory's path comes from TMPDIR, and nbconvert globs it too."""
    converter, observed, _ = route
    patterned = tmp_path / "tmp[1]"
    patterned.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(patterned))
    (tree / "nb.ipynb").write_bytes(as_nbformat_writes(notebook("python", None)))

    (converted,) = convert_one(converter, tree / "nb.ipynb", monkeypatch)

    (call,) = observed.calls
    assert str(patterned) in str(call["notebook"])
    assert converted.read_text() == "x = 1\n"


class TestAFailedConversionIsRecorded:
    """A notebook that was not converted is in the results row and fails the gate."""

    def test_nbconvert_exiting_non_zero(self, direct, tree, monkeypatch):
        converter, observed, _ = direct
        observed.result = lambda argv: subprocess.CompletedProcess(argv, 1, "", "no")
        (tree / "nb.ipynb").write_bytes(as_nbformat_writes(notebook("python", None)))

        assert convert_one(converter, tree / "nb.ipynb", monkeypatch) == []

        assert failed(converter) == [
            {"path": "nb.ipynb", "reason": "nbconvert exited with code 1"}
        ]
        assert gate(converter) == [("jupyter", "could not convert 1 input: nb.ipynb")]

    def test_nbconvert_exiting_zero_without_output(self, direct, tree, monkeypatch):
        converter, observed, _ = direct
        observed.result = lambda argv: subprocess.CompletedProcess(argv, 0, "", "")
        (tree / "nb.ipynb").write_bytes(as_nbformat_writes(notebook("python", None)))

        assert convert_one(converter, tree / "nb.ipynb", monkeypatch) == []

        assert failed(converter) == [
            {"path": "nb.ipynb", "reason": "nbconvert exited 0 but wrote no output"}
        ]
        assert gate(converter)[0][0] == "jupyter"

    def test_uv_failing_with_no_jupyter_to_fall_back_to(
        self, make_converter, tree, outside, monkeypatch
    ):
        converter = make_converter()
        converter.use_uv_tool = True
        monkeypatch.setattr(
            converter, "_execute_nbconvert_via_uv", lambda *a, **k: False
        )
        empty = outside / "empty-bin"
        empty.mkdir(parents=True)
        monkeypatch.setenv("PATH", str(empty))
        replace_subprocess(monkeypatch, refuse_direct_route)
        (tree / "nb.ipynb").write_bytes(as_nbformat_writes(notebook("python", None)))

        assert convert_one(converter, tree / "nb.ipynb", monkeypatch) == []

        ((path, reason),) = [(r["path"], r["reason"]) for r in failed(converter)]
        assert path == "nb.ipynb"
        assert reason == (
            "uv could not run nbconvert, and no other jupyter-nbconvert is run in its place"
        )

    def test_the_gate_names_at_most_five_and_counts_the_rest(
        self, direct, tree, monkeypatch
    ):
        converter, observed, _ = direct
        observed.result = lambda argv: subprocess.CompletedProcess(argv, 1, "", "")
        names = [f"n{i}.ipynb" for i in range(7)]
        for name in names:
            (tree / name).write_bytes(as_nbformat_writes(notebook("python", None)))
        monkeypatch.setattr(
            f"{jupyter_converter.__name__}.scan_set",
            lambda **kw: [str(tree / n) for n in names],
        )

        converter.convert()

        assert gate(converter) == [
            (
                "jupyter",
                (
                    "could not convert 7 inputs: n0.ipynb, n1.ipynb, n2.ipynb, "
                    "n3.ipynb, n4.ipynb and 2 more"
                ),
            )
        ]


class TestTheDirectRouteRunsAResolvedNbconvert:
    """``jupyter-nbconvert`` is run by an absolute path, never one from the cwd or tree.

    On Windows a program started by name is looked for in the working directory before
    PATH, and ``shutil.which`` does the same; ASH usually runs from the repository it
    scans. On every platform an empty, ``.`` or relative PATH entry names a directory
    under the working directory. And a copy on an absolute PATH entry inside the
    scanned tree is refused unless the operator sets ASH_ALLOW_IN_TREE_TOOLS.
    """

    def notebook_in(self, tree: Path) -> Path:
        (tree / "nb.ipynb").write_bytes(as_nbformat_writes(notebook("python", None)))
        return tree / "nb.ipynb"

    def test_one_reached_only_through_the_working_directory_is_not_run(
        self, direct, tree, monkeypatch, ash_warnings
    ):
        converter, observed, _ = direct
        fake_executable(tree, NBCONVERT)
        fake_executable(tree / "bin", NBCONVERT)
        monkeypatch.setenv("PATH", os.pathsep.join(["", ".", "bin"]))
        monkeypatch.chdir(tree)

        assert convert_one(converter, self.notebook_in(tree), monkeypatch) == []

        assert observed.calls == [], "a jupyter-nbconvert in the cwd was run"
        ((_, reason),) = [(r["path"], r["reason"]) for r in failed(converter)]
        # The record carries a fixed, path-free sentence; the lookup's own
        # words (why no copy could be run) are logged once.
        assert reason == (
            "the jupyter-nbconvert the dependency check chose cannot be used now, "
            "and no other jupyter-nbconvert is run in its place"
        )
        assert [m for m in ash_warnings if "nbconvert is not run for" in m], (
            ash_warnings
        )

    def test_an_installed_one_later_on_path_is_run_instead(
        self, direct, tree, monkeypatch
    ):
        converter, observed, nbconvert = direct
        fake_executable(tree, NBCONVERT)
        monkeypatch.setenv("PATH", os.pathsep.join([".", str(nbconvert.parent)]))
        monkeypatch.chdir(tree)

        (converted,) = convert_one(converter, self.notebook_in(tree), monkeypatch)

        (call,) = observed.calls
        assert call["argv"][0] == str(nbconvert)
        assert converted.read_text() == "x = 1\n"

    def test_windows_searching_the_working_directory_first_does_not_pick_its_copy(
        self, direct, tree, monkeypatch
    ):
        converter, observed, nbconvert = direct
        local = fake_executable(tree, NBCONVERT)
        real_which = subprocess_utils.shutil.which

        def windows_which(cmd, mode=os.F_OK | os.X_OK, path=None):
            # shutil.which on Windows: the working directory, then PATH.
            if not os.path.dirname(cmd):
                here = os.path.join(os.curdir, cmd)
                if os.path.isfile(here):
                    return here
            return real_which(cmd, mode, path)

        monkeypatch.setattr(subprocess_utils.shutil, "which", windows_which)
        monkeypatch.chdir(tree)
        # The emulation does what Windows does: the bare name finds the local copy.
        assert Path(windows_which(local.name)).resolve() == local.resolve()

        (converted,) = convert_one(converter, self.notebook_in(tree), monkeypatch)

        (call,) = observed.calls
        assert call["argv"][0] == str(nbconvert)
        assert converted.read_text() == "x = 1\n"

    def test_an_in_tree_copy_on_an_absolute_path_entry_is_refused(
        self, direct, tree, monkeypatch, ash_warnings
    ):
        """An activated in-repo virtual environment, as ``uv run ash scan .`` gives."""
        converter, observed, nbconvert = direct
        monkeypatch.delenv("ASH_ALLOW_IN_TREE_TOOLS", raising=False)
        in_tree = fake_executable(tree / ".venv" / "bin", NBCONVERT)
        monkeypatch.setenv(
            "PATH", os.pathsep.join([str(in_tree.parent), str(nbconvert.parent)])
        )

        convert_one(converter, self.notebook_in(tree), monkeypatch)

        (call,) = observed.calls
        assert call["argv"][0] == str(nbconvert)
        assert [m for m in ash_warnings if str(in_tree) in m], ash_warnings

    def test_with_no_other_copy_nothing_runs(self, direct, tree, monkeypatch):
        converter, observed, _ = direct
        monkeypatch.delenv("ASH_ALLOW_IN_TREE_TOOLS", raising=False)
        in_tree = fake_executable(tree / ".venv" / "bin", NBCONVERT)
        monkeypatch.setenv("PATH", str(in_tree.parent))

        assert convert_one(converter, self.notebook_in(tree), monkeypatch) == []

        assert observed.calls == []
        assert [r["path"] for r in failed(converter)] == ["nb.ipynb"]

    def test_the_operators_opt_in_runs_the_in_tree_copy_with_a_warning(
        self, direct, tree, monkeypatch, ash_warnings
    ):
        converter, observed, nbconvert = direct
        monkeypatch.setenv("ASH_ALLOW_IN_TREE_TOOLS", "1")
        in_tree = fake_executable(tree / ".venv" / "bin", NBCONVERT)
        monkeypatch.setenv(
            "PATH", os.pathsep.join([str(in_tree.parent), str(nbconvert.parent)])
        )

        (converted,) = convert_one(converter, self.notebook_in(tree), monkeypatch)

        (call,) = observed.calls
        assert call["argv"][0] == str(in_tree)
        assert [
            m
            for m in ash_warnings
            if "inside the scanned tree" in m and str(in_tree) in m
        ], ash_warnings
        assert converted.read_text() == "x = 1\n"


class TestTheVersionProbe:
    """validate_plugin_dependencies' direct check runs the same resolved program."""

    def probe_calls(self, monkeypatch) -> list[dict]:
        calls: list[dict] = []

        def run(argv, *args, **kwargs):
            calls.append({"argv": list(argv), "cwd": kwargs.get("cwd")})
            return subprocess.CompletedProcess(argv, 0, "7.17.1\n", "")

        replace_subprocess(monkeypatch, run)
        return calls

    def test_it_runs_the_absolute_path_in_an_empty_directory(
        self, make_converter, tree, outside, monkeypatch
    ):
        converter = make_converter()
        converter.use_uv_tool = False
        nbconvert = fake_executable(outside / "bin", NBCONVERT)
        fake_executable(tree, NBCONVERT)
        monkeypatch.setenv("PATH", os.pathsep.join([".", str(nbconvert.parent)]))
        monkeypatch.chdir(tree)
        calls = self.probe_calls(monkeypatch)

        assert converter.validate_plugin_dependencies() is True

        (call,) = calls
        assert call["argv"] == [str(nbconvert), "--version"]
        assert call["cwd"] is not None
        assert not Path(call["cwd"]).resolve().is_relative_to(tree.resolve())

    def test_one_only_in_the_working_directory_is_not_probed(
        self, make_converter, tree, monkeypatch
    ):
        converter = make_converter()
        converter.use_uv_tool = False
        fake_executable(tree, NBCONVERT)
        monkeypatch.setenv("PATH", os.pathsep.join(["", "."]))
        monkeypatch.chdir(tree)
        calls = self.probe_calls(monkeypatch)

        assert converter.validate_plugin_dependencies() is False
        assert calls == []


class TestTheCopyIsStagedSafely:
    @pytest.mark.parametrize(
        "extension, kept",
        [
            (".r", True),
            (".c++", True),
            ("/../../escaped.py", False),
            ("..\\..\\escaped.py", False),
            ("", False),
            (7, False),
        ],
    )
    def test_only_a_plain_file_extension_is_kept(self, tmp_path, extension, kept):
        """The script exporter appends ``file_extension`` to the output's name."""
        nb = notebook("R", None)
        nb["metadata"]["language_info"]["file_extension"] = extension
        staged = tmp_path / "notebook.ipynb"

        JupyterConverter._stage_notebook(as_nbformat_writes(nb), staged)

        language_info = json.loads(staged.read_bytes())["metadata"]["language_info"]
        assert ("file_extension" in language_info) is kept
        if kept:
            assert language_info["file_extension"] == extension

    def test_a_script_output_keeps_its_extension(self, direct, tree, monkeypatch):
        """An R notebook converts to ``<name>-converted.r``, beside the Python ones."""
        converter, _, _ = direct
        nb = notebook("R", None, "x <- 1\n")
        nb["metadata"]["language_info"]["file_extension"] = ".r"
        (tree / "nb.ipynb").write_bytes(as_nbformat_writes(nb))
        monkeypatch.chdir(tree)

        (converted,) = convert_one(converter, tree / "nb.ipynb", monkeypatch)

        assert converted == converter.results_dir / "nb__ipynb-converted.r"
        assert converted.read_text() == "x <- 1\n"
