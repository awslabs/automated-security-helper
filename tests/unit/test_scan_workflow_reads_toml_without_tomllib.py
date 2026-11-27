"""The config-ref steps read a TOML config, and write one when the ref has none.

Why this file exists
--------------------
The step "Read the tool config files the config names from config-ref" parses the
fetched config with a short Python program of its own, run in the uv environment that
holds the installed ASH. ``tomllib`` is in the standard library from Python 3.11. The
``python-version`` input reaches setup-python as given, so a caller can still name 3.10
for an ASH release whose ``requires-python`` admits it, and there the program needs a
TOML reader from that environment. Every release from v3.0.0 through v3.7.1 declares
``toml`` for it. v3.8.0 declares ``tomli`` instead and keeps ``toml`` as a development
dependency only. The program imported ``toml`` and nothing else, so a TOML config failed
with ASH v3.8.0 on Python 3.10, at an import error that named a module that release does
not bring.

The step before it, "Read the ASH config from config-ref", has a part here too. With
``config-ref-missing: defaults``, a ref that has no file at ``config`` gets an empty
config written in its place, and ASH and the program below both read that file by its
name. It was ``{}`` for every name. That is an empty mapping in YAML and JSON and not a
TOML document, so for a TOML ``config`` the program stopped on it, in the one case the
input exists for: the pull request that adds a repository's first config. An empty file
is the empty config for a TOML name, except ``pyproject.toml``, which ASH reads only
through its ``[tool.ash]`` table and refuses without one.

What this asserts
-----------------
1. With ``tomllib`` present the program parses with it, whatever else is installed.
2. Without it the program parses with ``tomli`` when that is present, and with ``toml``
   when only that is. ``tomli`` goes first because it reads TOML 1.0.
3. What the reader returns is what the step goes on to use: an option in the parsed
   config is the one the step refuses.
4. With none of the three the step refuses in the form its other refusals take (an
   ``::error::`` line and exit 1), and the line names all three.
5. The extraction finds the program. This is a control: an extraction that found nothing,
   or some other text, would leave every other test here checking nothing.
6. With ``config-ref-missing: defaults`` and a ``config`` that its ref lacks, the file
   the first step writes for a TOML name is read by the program's TOML branch (for
   ``pyproject.toml`` too), and the step that runs the program accepts it.
7. ASH's own loader reads that file as the empty config a YAML ``{}`` is. This holds for
   a TOML name in any letter case (ASH takes the format from the suffix in either, and
   the program's own checks match lower case only), and for a ``pyproject.toml`` wherever
   it sits (ASH reads it only through its ``[tool.ash]`` table, and refuses a file
   without one). A name that only resembles it, such as ``not-pyproject.toml``, is a
   config at its top level and gets no such table.
8. A YAML or JSON name keeps ``{}``.

How it runs
-----------
The program is the heredoc of the workflow step, executed in this process. Each of the
three readers is either replaced in ``sys.modules`` by a stand-in or set to ``None``,
which makes ``import`` raise ``ModuleNotFoundError`` as it does on a Python that lacks
the module. A stand-in records that it was called and parses with this interpreter's
``tomllib``. None of the configs here names a file to fetch, so nothing reaches git.

The placeholder cases do reach git. They run the first step's own shell, as
test_required_scan_reads_the_base_branchs_config.py does, against a scratch repository
whose base commit lacks the config, and read the file it wrote. Those are integration
tests; the rest of this file is unit.

What it does not cover
----------------------
A real Python 3.10 with the real ``tomli`` or ``toml`` installed, and the uv environment
that decides which of them is present. ASH's loader runs here on this interpreter, with
its ``tomllib``.
"""

from __future__ import annotations

import ast
import os
import re
import shutil
import sys
import tomllib
import types
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from automated_security_helper.config.resolve_config import load_config_file
from tests.unit.test_required_scan_reads_the_base_branchs_config import (
    Repository,
    _pull_request,
    _run_config_ref_step,
)
from tests.utils import github_actions as ga

SCAN_WORKFLOW = ga.WORKFLOWS_DIR / "run-ash-security-scan.yml"
STEP_ID = "config-ref-files"

#: The program the step hands to ``python -I -``: the text between the heredoc's opener
#: and its closing ``PY`` line, which YAML has already de-indented.
HEREDOC = re.compile(r"<<'PY'\n(.*?)\nPY\n", re.DOTALL)

#: The TOML readers, in the order the program should try them.
READERS = ("tomllib", "tomli", "toml")

#: A config with no tool config file to fetch: the step passes it on as it is.
PLAIN = 'project_name = "probe"\n'

#: A config naming a tool config outside the repository, which the step refuses by the
#: option's name. Only what the reader parsed can tell it that, and the refusal comes
#: before anything is fetched, so git never starts.
OUTSIDE = '[scanners.bandit.options]\nconfig_file = "../outside.yaml"\n'

#: What the placeholder cases need: the step's own shell, which runs git.
NEEDS_BASH_AND_GIT = pytest.mark.skipif(
    os.name == "nt" or shutil.which("bash") is None or shutil.which("git") is None,
    reason="the config-ref steps are bash steps that run git on ubuntu-latest",
)

#: Config names the program reads as TOML, since it matches the suffix in lower case.
#: `not-pyproject.toml` is a control: only a file named exactly pyproject.toml is read
#: through a [tool.ash] table.
TOML_NAMES = (".ashrc.toml", "config/ash.toml", "not-pyproject.toml")

#: A pyproject.toml, wherever it sits: ASH reads its [tool.ash] table, and refuses the
#: file when it has none.
PYPROJECT_NAMES = ("pyproject.toml", "packages/api/pyproject.toml")

#: TOML names in capitals. ASH takes a file's format from its suffix in any letter case.
#: The program's own checks match lower case only, so it reads these as YAML.
CAPITAL_NAMES = ("ASH.TOML", "sub/PyProject.TOML")

#: Names that are not TOML. `toml/ash.yaml` is a control for a match on the word.
OTHER_NAMES = (".ash.yaml", "ash.yml", ".ash/ash.json", "toml/ash.yaml")

ALL_NAMES = TOML_NAMES + PYPROJECT_NAMES + CAPITAL_NAMES + OTHER_NAMES


def _program() -> str:
    """The step's Python program, as the workflow hands it to the interpreter."""
    steps = [
        step
        for step in ga.load_workflow(SCAN_WORKFLOW).jobs["ash"].get("steps") or []
        if step.get("id") == STEP_ID
    ]
    assert len(steps) == 1, f"expected one step with id {STEP_ID}, found {len(steps)}"
    programs = HEREDOC.findall(steps[0]["run"])
    assert len(programs) == 1, f"expected one heredoc, found {len(programs)}"
    return programs[0] + "\n"


def _reader(name: str, used: list[str]) -> types.ModuleType:
    """A stand-in for a reader: it records its use and parses with ``tomllib``."""
    module = types.ModuleType(name)

    def loads(text: str) -> dict:
        used.append(name)
        return tomllib.loads(text)

    module.loads = loads
    return module


@dataclass
class Run:
    """What one run of the program did."""

    config: Path
    used: list[str]  # the readers that parsed, in order
    output: str  # what the program wrote to GITHUB_OUTPUT
    exit_code: int | None  # None when the program finished without exiting
    stdout: str
    stderr: str


@pytest.fixture
def run_program(tmp_path, monkeypatch, capsys):
    """Run the step's program here, with only the named readers importable."""
    program = compile(_program(), "<config-ref-files>", "exec")

    def run(
        importable: tuple[str, ...], text: str = PLAIN, name: str = ".ashrc.toml"
    ) -> Run:
        used: list[str] = []
        for reader in READERS:
            stand_in = _reader(reader, used) if reader in importable else None
            monkeypatch.setitem(sys.modules, reader, stand_in)
        config = tmp_path / name
        config.write_text(text, encoding="utf-8")
        output = tmp_path / "github-output"
        environment = {
            "CONFIG_FILE": str(config),
            "CONFIG_COMMIT": "0" * 40,
            "CONFIG_REF": "refs/pull/1/merge",
            "DEST_ROOT": str(tmp_path / "copies"),
            "GITHUB_OUTPUT": str(output),
        }
        for name, value in environment.items():
            monkeypatch.setenv(name, value)
        # The program installs an excepthook of its own; the interpreter's comes back.
        monkeypatch.setattr(sys, "excepthook", sys.excepthook)
        namespace = {"__name__": "config_ref_files"}
        exit_code = None
        try:
            exec(program, namespace)  # noqa: S102  # nosec B102
        except SystemExit as stop:
            exit_code = stop.code
        captured = capsys.readouterr()
        return Run(
            config=config,
            used=used,
            output=output.read_text(encoding="utf-8") if output.exists() else "",
            exit_code=exit_code,
            stdout=captured.out,
            stderr=captured.err,
        )

    return run


@pytest.mark.unit
class TestTheExtractionFindsTheProgram:
    def test_it_is_the_program_that_reads_the_config(self):
        tree = ast.parse(_program())
        functions = {n.name for n in tree.body if isinstance(n, ast.FunctionDef)}
        assert {"fail", "fetch", "one_line"} <= functions, sorted(functions)


@pytest.mark.unit
class TestTheFirstReaderThatImportsParsesTheConfig:
    @pytest.mark.parametrize(
        "importable,expected",
        [
            pytest.param(("tomllib",), "tomllib", id="tomllib alone"),
            pytest.param(READERS, "tomllib", id="tomllib before the others"),
            pytest.param(("tomli",), "tomli", id="tomli alone, as in ASH v3.8.0"),
            pytest.param(("tomli", "toml"), "tomli", id="tomli before toml"),
            pytest.param(("toml",), "toml", id="toml alone, as in ASH v3.7.1"),
        ],
    )
    def test_the_config_is_read_with_the_first_of_them(
        self, run_program, importable, expected
    ):
        run = run_program(importable)
        assert run.exit_code is None, run
        assert run.used == [expected], run
        assert run.output == f"path={run.config}\n", run

    @pytest.mark.parametrize("reader", READERS)
    def test_what_the_reader_returns_is_what_the_step_goes_on_to_use(
        self, run_program, reader
    ):
        run = run_program((reader,), OUTSIDE)
        assert run.used == [reader], run
        assert run.exit_code == 1, run
        assert "scanners.bandit.options.config_file" in run.stdout, run


@pytest.mark.unit
class TestWithNoReaderTheStepRefusesInItsOwnWords:
    def test_the_refusal_names_all_three_readers(self, run_program):
        run = run_program(())
        assert run.exit_code == 1, run
        assert run.used == [], run
        assert run.output == "", run
        (line,) = run.stdout.splitlines()
        assert line.startswith("::error::"), run
        for reader in READERS:
            assert re.search(rf"\b{reader}\b", line), (reader, line)


@dataclass
class MissingConfig:
    """What the config-ref steps did for a config their ref does not have."""

    placeholder: Path  # what the first step wrote where the config would have been
    run: ga.StepRun  # the last step that ran: the one that reads the placeholder
    steps: dict[str, Any]  # each step's outcome, outputs and stdout, by step id


def _missing_at_its_ref(root: Path, name: str) -> MissingConfig:
    """Run the config-ref steps for `name`, which their ref lacks, under `defaults`."""
    root.mkdir()
    repo = Repository(root, base_files={})
    inputs = ga.call_inputs(
        {
            "with": {
                "config": name,
                "config-ref": repo.base_sha,
                "config-ref-missing": "defaults",
            }
        },
        ga.load_workflow(SCAN_WORKFLOW),
        ga.base_context(),
    )
    context = _pull_request(repo.base_sha, fork=False)
    run, steps = _run_config_ref_step(repo, context, inputs)
    assert run is not None, "no step reads the config from config-ref"
    fetch = steps["config-ref"]
    assert fetch["outcome"] == "success", run.describe()
    placeholder = Path(fetch["outputs"]["path"])
    assert placeholder.name == Path(name).name, (name, placeholder)
    return MissingConfig(placeholder, run, steps)


@pytest.mark.integration
@NEEDS_BASH_AND_GIT
class TestAConfigItsRefLacksIsReplacedByAnEmptyConfigOfItsOwnFormat:
    """The file written for the missing config is empty in the format its name says."""

    @pytest.mark.parametrize("name", TOML_NAMES + PYPROJECT_NAMES)
    def test_the_programs_toml_branch_reads_it(self, tmp_path, run_program, name):
        missing = _missing_at_its_ref(tmp_path / "steps", name)
        text = missing.placeholder.read_text(encoding="utf-8")
        run = run_program(READERS, text, Path(name).name)
        assert run.exit_code is None, run
        assert run.used == ["tomllib"], run
        assert run.output == f"path={run.config}\n", run

    @pytest.mark.parametrize("name", [".ashrc.toml", "pyproject.toml", ".ash.yaml"])
    def test_the_step_that_runs_the_program_accepts_it(self, tmp_path, name):
        missing = _missing_at_its_ref(tmp_path / "steps", name)
        assert missing.run.proc.returncode == 0, missing.run.describe()
        files = missing.steps["config-ref-files"]
        assert files["outcome"] == "success", files
        assert files["outputs"]["path"] == str(missing.placeholder), files
        warned = missing.steps["config-ref"]["stdout"]
        assert "::warning::" in warned and "default config" in warned, warned

    @pytest.mark.parametrize("name", ALL_NAMES)
    def test_ash_loads_it_as_an_empty_config(self, tmp_path, name):
        missing = _missing_at_its_ref(tmp_path / "steps", name)
        empty = tmp_path / "empty.yaml"
        empty.write_text("{}\n", encoding="utf-8")
        loaded, _ = load_config_file(missing.placeholder)
        expected, _ = load_config_file(empty)
        assert loaded.data == expected.data, missing.placeholder.read_text()

    @pytest.mark.parametrize("name", OTHER_NAMES)
    def test_a_name_that_is_not_toml_keeps_the_empty_mapping(self, tmp_path, name):
        missing = _missing_at_its_ref(tmp_path / "steps", name)
        assert missing.placeholder.read_text(encoding="utf-8").strip() == "{}"
