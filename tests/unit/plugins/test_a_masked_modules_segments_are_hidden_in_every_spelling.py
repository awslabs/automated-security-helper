# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A masked module's segments are hidden in every spelling a failure prints.

The load-wide needles were the masked name, its "/" and "\\" path spellings
and its dotted PREFIXES, so a text quoting a segment AFTER the last masked
boundary printed it in clear: a from-import or attribute error quotes the
last segment alone ("cannot import name 'leaf' from ..."), a stale-cache
message prints "__pycache__/leaf.cpython-*.pyc", and a compile error prints
"leaf.py". The needles now also carry every proper dotted SUFFIX of the
masked name (with its path spellings), and the ".py" and "__pycache__"
".cpython" file spellings of the hidden leaf segment, so those shapes hide
too.

Three bounds keep the suffixes from blanking readable text: a suffix
shorter than the anywhere band (``MIN_ANYWHERE_LENGTH``) is matched too
widely to be a safe needle, one equal to a word ASH's own text prints (a
namespace root, the opt-in plugin root, a plugin kind) is public, and the
opt-in plugin root ``automated_security_helper.plugin_modules`` is itself a
readable root -- the namespace rule's text names it.

Cells by section: A, one spelling per cell, read from a file beside a
literal module so each surface holds exactly that spelling; B, natural
three-segment failures (a missing or raising top, middle or leaf); C,
natural shapes that quote the last segment alone; D, the must-not-flag
controls (roots, fixed words, the short-piece floor, a label pin).
"""

from __future__ import annotations

import importlib.util
import logging
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

import pytest

from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit

TRACEBACK = "failure traceback"
RAISES = "raise RuntimeError('module body refuses')\n"
RAISES_FROM_FILE = (
    "import pathlib\n"
    "raise RuntimeError((pathlib.Path(__file__).parent / 'msg.txt')"
    ".read_text(encoding='utf-8'))\n"
)

T = "segtop_ash_plugins"
S1 = "kqmidsegx"
S2 = "jzleafsegw"
P = f"{T}.{S1}.{S2}"
SEGMENTS = (T, S1, S2)
LIT = "seglit_ash_plugins"
PAIR_OTHER = "segpairq_ash_plugins"


class _Sink(logging.Handler):
    def __init__(self):
        super().__init__(level=1)
        self.records: List[logging.LogRecord] = []

    def emit(self, record):
        self.records.append(record)


@pytest.fixture
def sink():
    handler = _Sink()
    level = ASH_LOGGER.level
    ASH_LOGGER.addHandler(handler)
    ASH_LOGGER.setLevel(1)
    yield handler
    ASH_LOGGER.removeHandler(handler)
    ASH_LOGGER.setLevel(level)


def _ours(name: str) -> bool:
    return name in ("ash_plugins", "ab") or name.startswith(
        ("seg", "ash_plugins.", "ab.")
    )


@pytest.fixture
def site(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    for name in ("ASH_PLUGIN_MODULES", "ASH_CONFIG", "ASH_SOURCE_DIR"):
        monkeypatch.delenv(name, raising=False)
    root = tmp_path / "seg-site"
    root.mkdir()
    for name in [m for m in sys.modules if _ours(m)]:
        monkeypatch.delitem(sys.modules, name, raising=False)
    monkeypatch.syspath_prepend(str(root))
    yield root
    for name in [m for m in sys.modules if _ours(m)]:
        sys.modules.pop(name, None)


def _plant(root: Path, files: Dict[str, str]) -> None:
    for relative, body in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")


def _config_file(path: Path, entries: Sequence[str]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "".join(f"  - {entry}\n" for entry in entries)
    path.write_text(
        f"project_name: demo\nash_plugin_modules:\n{body}", encoding="utf-8"
    )
    return path


def _engine_load(tmp_path: Path, entries: Sequence[str], sink: _Sink):
    """The scan engine's own loader call: the config's names, labels and
    values, then the refusal a configured failure raises. The returned
    sources are every surface a failure's text reaches."""
    from automated_security_helper.config.plugin_module_trust import (
        config_module_names,
        split_plugin_modules,
    )
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.plugins.loader import (
        PluginModuleImportError,
        load_additional_plugin_modules,
        refuse_failed_plugin_imports,
    )
    from automated_security_helper.utils.error_text import config_environment_values

    cfg = _config_file(tmp_path / "seg-config" / "cfg.yaml", entries)
    config = resolve_config(config_path=str(cfg))
    names = split_plugin_modules(list(config.ash_plugin_modules))
    shown = config_module_names(config) or None
    record: Dict[str, Any] = {}
    load_additional_plugin_modules(
        names, shown=shown, record=record, values=config_environment_values(config)
    )
    refusal = ""
    try:
        refuse_failed_plugin_imports(names, record, shown=shown)
    except PluginModuleImportError as error:
        refusal = str(error)
    sources = {
        f"log{i}:{r.levelname}:{r.filename}:{r.lineno}": r.getMessage()
        for i, r in enumerate(sink.records)
    }
    sources["record-texts"] = repr([f.recorded for f in record.values()])
    sources["refusal"] = refusal
    return names, record, shown, sources


def _holding(sources: Dict[str, str], names: Sequence[str]) -> Dict[str, str]:
    """Each source that holds a name, its lines with the names as tokens, so
    an assertion message cannot itself print a masked value."""
    held = {}
    for where, body in sources.items():
        if not any(name in body for name in names):
            continue
        lines = [line for line in body.splitlines() if any(n in line for n in names)]
        shown = " || ".join(lines)
        for index, name in sorted(enumerate(names), key=lambda p: -len(p[1])):
            shown = shown.replace(name, f"[[NAME-{index}]]")
        held[where] = shown[:500]
    return held


# --- A: one spelling per cell -----------------------------------------------

WIN = "C:\\site\\"


def _spelling(kind: str, site: Path) -> str:
    here = str(site)
    return {
        "dotted": f"cannot use {T}.{S1}.{S2} here",
        "slash": f"cannot use {T}/{S1}/{S2} here",
        "backslash": "cannot use " + WIN + f"{T}\\{S1}\\{S2}" + " here",
        "backslash-repr": "cannot open " + repr(WIN + "\\".join([T, S1, S2 + ".py"])),
        "py-file": f"cannot read {here}/{T}/{S1}/{S2}.py",
        "py-file-win": "cannot read " + WIN + "\\".join([T, S1, S2 + ".py"]),
        "pyc-cache": f"stale cache {here}/{T}/{S1}/__pycache__/{S2}.cpython-314.pyc",
        "pyc-cache-win": "stale cache "
        + WIN
        + "\\".join([T, S1, "__pycache__", S2 + ".cpython-314.pyc"]),
        "package-dir": f"cannot list {here}/{T}/{S1}/",
        "package-dir-win": "cannot list " + WIN + f"{T}\\{S1}" + "\\",
        "prefix-dotted": f"No module named '{T}.{S1}'",
        "top-alone": f"No module named '{T}'",
        "leaf-basename": f"cannot compile {S2}.py",
    }[kind]


SPELLINGS = (
    "backslash",
    "backslash-repr",
    "dotted",
    "leaf-basename",
    "package-dir",
    "package-dir-win",
    "prefix-dotted",
    "py-file",
    "py-file-win",
    "pyc-cache",
    "pyc-cache-win",
    "slash",
    "top-alone",
)


def _spelling_files(kind: str, site: Path) -> Dict[str, str]:
    return {
        f"{T}/__init__.py": "",
        f"{T}/{S1}/__init__.py": "",
        f"{T}/{S1}/{S2}.py": "",
        f"{PAIR_OTHER}/__init__.py": "",
        f"{LIT}/__init__.py": RAISES_FROM_FILE,
        f"{LIT}/msg.txt": _spelling(kind, site),
    }


@pytest.mark.parametrize("shape", ["pair", "single"])
@pytest.mark.parametrize("kind", SPELLINGS)
def test_seg_one_spelling_hides_every_segment(
    tmp_path: Path, monkeypatch, site: Path, sink: _Sink, kind: str, shape: str
):
    _plant(site, _spelling_files(kind, site))
    if shape == "single":
        monkeypatch.setenv("ASH_SEG_ONE", P)
        entries = ["${ASH_SEG_ONE}", LIT]
    else:
        monkeypatch.setenv("ASH_SEG_TWO", f"{PAIR_OTHER},{P}")
        entries = ["${ASH_SEG_TWO}", LIT]
    names, record, shown, sources = _engine_load(tmp_path, entries, sink)
    if sorted(record) != [LIT] or record[LIT].kind != "RuntimeError":
        raise RuntimeError(("premise: only the literal module failed", sorted(record)))
    if (shown or {}).get(P, P) == P or (shown or {}).get(LIT) != LIT:
        raise RuntimeError(("premise: P masked, the literal shown", shown))
    if not any(TRACEBACK in b for b in sources.values()):
        raise RuntimeError("premise: the DEBUG traceback was logged")
    message = (site / LIT / "msg.txt").read_text(encoding="utf-8")
    if not any(s in message for s in SEGMENTS):
        raise RuntimeError("premise: the spelling names a segment")
    held = _holding(sources, SEGMENTS)
    assert not held, held
    # The spelling reached the record and was masked there, not dropped.
    assert "<value>" in sources["record-texts"], sources["record-texts"][:300]


@pytest.mark.parametrize("kind", ["dotted", "pyc-cache", "slash"])
def test_seg_control_a_literal_value_shows_its_segments(
    tmp_path: Path, site: Path, sink: _Sink, kind: str
):
    """Must-fail control for the cells above: with the value written in the
    file (nothing masked), the same spelling reaches the record, the WARNING,
    the refusal and the DEBUG traceback in clear."""
    _plant(site, _spelling_files(kind, site))
    names, record, shown, sources = _engine_load(tmp_path, [P, LIT], sink)
    if sorted(record) != [LIT]:
        raise RuntimeError(("premise: only the literal module failed", sorted(record)))
    held = _holding(sources, SEGMENTS)
    for where in ("record-texts", "refusal"):
        assert where in held, (where, held)
    assert any(":WARNING:" in w for w in held), held
    assert any(TRACEBACK in sources[w] for w in held if w.startswith("log")), held


# --- B: natural three-segment shapes ----------------------------------------

DOTTED3: Dict[str, Dict[str, str]] = {
    "env3-top-missing": {},
    "env3-mid-missing": {f"{T}/__init__.py": ""},
    "env3-top-parent-raises": {
        f"{T}/__init__.py": RAISES,
        f"{T}/{S1}/__init__.py": "",
        f"{T}/{S1}/{S2}.py": "",
    },
    "env3-mid-parent-raises": {
        f"{T}/__init__.py": "",
        f"{T}/{S1}/__init__.py": RAISES,
        f"{T}/{S1}/{S2}.py": "",
    },
    "env3-leaf-raises": {
        f"{T}/__init__.py": "",
        f"{T}/{S1}/__init__.py": "",
        f"{T}/{S1}/{S2}.py": RAISES,
    },
}


@pytest.mark.parametrize("shape", sorted(DOTTED3))
def test_seg_three_segment_entry_hides_every_segment(
    tmp_path: Path, monkeypatch, site: Path, sink: _Sink, shape: str
):
    _plant(site, DOTTED3[shape])
    monkeypatch.setenv("ASH_SEG_DOT3", P)
    names, record, shown, sources = _engine_load(tmp_path, ["${ASH_SEG_DOT3}"], sink)
    if names != [P] or sorted(record) != [P]:
        raise RuntimeError(("premise: the entry failed", names, sorted(record)))
    if not any(TRACEBACK in b for b in sources.values()):
        raise RuntimeError("premise: the DEBUG traceback was logged")
    held = _holding(sources, SEGMENTS)
    assert not held, held


@pytest.mark.parametrize("shape", ["env3-mid-missing", "env3-mid-parent-raises"])
def test_seg_control_literal_three_segment_entry_quotes_the_middle(
    tmp_path: Path, site: Path, sink: _Sink, shape: str
):
    """Must-fail control: written literally, the same failure's text does
    quote the middle segment (the frame or the missing package)."""
    _plant(site, DOTTED3[shape])
    names, record, shown, sources = _engine_load(tmp_path, [P], sink)
    if sorted(record) != [P]:
        raise RuntimeError(("premise: the entry failed", sorted(record)))
    held = _holding(sources, (S1,))
    assert held, sources["record-texts"][:300]


# --- C: natural shapes that quote the last segment alone --------------------

ROOT_LEAF = "kqrootleafz"
LEAFY: Dict[str, Tuple[Dict[str, str], str]] = {
    # files, the env-read value; the literal module LIT is always configured.
    "from-import-leaf": (
        {
            f"{T}/__init__.py": "",
            f"{T}/{S1}/__init__.py": "",
            f"{LIT}/__init__.py": f"from {T}.{S1} import {S2}\n",
        },
        P,
    ),
    "attribute-leaf": (
        {
            f"{T}/__init__.py": "",
            f"{T}/{S1}/__init__.py": "",
            f"{LIT}/__init__.py": f"import {T}.{S1}\n{T}.{S1}.{S2}\n",
        },
        P,
    ),
    "root-from-import": (
        {
            "ash_plugins/__init__.py": "",
            f"{LIT}/__init__.py": f"from ash_plugins import {ROOT_LEAF}\n",
        },
        f"ash_plugins.{ROOT_LEAF}",
    ),
}


@pytest.mark.parametrize("shape", sorted(LEAFY))
def test_seg_last_segment_alone(
    tmp_path: Path, monkeypatch, site: Path, sink: _Sink, shape: str
):
    files, value = LEAFY[shape]
    _plant(site, files)
    monkeypatch.setenv("ASH_SEG_LEAF", value)
    names, record, shown, sources = _engine_load(
        tmp_path, ["${ASH_SEG_LEAF}", LIT], sink
    )
    if sorted(record) != sorted([value, LIT]):
        raise RuntimeError(("premise: both failed", sorted(record)))
    if (shown or {}).get(value, value) == value or (shown or {}).get(LIT) != LIT:
        raise RuntimeError(("premise: the value masked, the literal shown", shown))
    segments = tuple(s for s in value.split(".") if s != "ash_plugins")
    held = _holding(sources, segments)
    assert not held, held


F4A = "kqfourmidaq"
F4B = "kqfourmidbq"
F4C = "kqfourleafq"
ROOT_MID = "kqrootmidnq"
MIDDLE: Dict[str, Tuple[Dict[str, str], str, Tuple[str, ...]]] = {
    # files, the env-read value, the middle segments the failure quotes alone.
    "from-import-middle": (
        {
            f"{T}/__init__.py": "",
            f"{LIT}/__init__.py": f"from {T} import {S1}\n",
        },
        P,
        (S1,),
    ),
    "attribute-middle": (
        {
            f"{T}/__init__.py": "",
            f"{LIT}/__init__.py": f"import {T}\n{T}.{S1}\n",
        },
        P,
        (S1,),
    ),
    "root-from-import-middle": (
        {
            "ash_plugins/__init__.py": "",
            f"{LIT}/__init__.py": f"from ash_plugins import {ROOT_MID}\n",
        },
        f"ash_plugins.{ROOT_MID}.{ROOT_LEAF}",
        (ROOT_MID,),
    ),
    "four-segment-infix": (
        {
            f"{T}/__init__.py": "",
            f"{T}/{F4A}/__init__.py": "",
            f"{LIT}/__init__.py": f"from {T}.{F4A} import {F4B}\n",
        },
        f"{T}.{F4A}.{F4B}.{F4C}",
        # CPython 3.14's "Did you mean" hint can quote the sibling segment
        # alone too, so both inner segments must be needles.
        (F4B, F4A),
    ),
}


@pytest.mark.parametrize("shape", sorted(MIDDLE))
def test_seg_middle_segment_alone(
    tmp_path: Path, monkeypatch, site: Path, sink: _Sink, shape: str
):
    """A segment that is neither a prefix nor a suffix of the masked value is
    quoted alone by a from-import or attribute failure ("cannot import name
    'mid' from ...", "has no attribute 'mid'"), which no whole-name, prefix
    or suffix needle matches: every contiguous inner run is a needle too."""
    files, value, middles = MIDDLE[shape]
    _plant(site, files)
    monkeypatch.setenv("ASH_SEG_MID", value)
    names, record, shown, sources = _engine_load(
        tmp_path, ["${ASH_SEG_MID}", LIT], sink
    )
    if LIT not in record:
        raise RuntimeError(("premise: the literal module failed", sorted(record)))
    if (shown or {}).get(value, value) == value or (shown or {}).get(LIT) != LIT:
        raise RuntimeError(("premise: the value masked, the literal shown", shown))
    if not any(m in (record[LIT].recorded or "") for m in middles) and not any(
        "<value>" in b for b in sources.values()
    ):
        raise RuntimeError(("premise: the failure quotes a middle segment", middles))
    held = _holding(sources, middles)
    assert not held, held


def test_seg_plugin_list_console_root_middle(
    tmp_path: Path, monkeypatch, site: Path, sink: _Sink
):
    """The root-middle shape through ``ash plugin list --config``, no
    ``--debug``: the console's exit-3 refusal hides the middle segment."""
    from typer.testing import CliRunner

    from automated_security_helper.cli.main import app

    files, value, middles = MIDDLE["root-from-import-middle"]
    _plant(site, files)
    monkeypatch.setenv("ASH_SEG_MID", value)
    cfg = _config_file(tmp_path / "seg-cli" / "cfg.yaml", ["${ASH_SEG_MID}", LIT])
    project = tmp_path / "seg-proj"
    project.mkdir()
    monkeypatch.chdir(project)
    result = CliRunner().invoke(app, ["plugin", "list", "--config", str(cfg)])
    if result.exit_code != 3:
        raise RuntimeError(("premise: the listing was refused", result.exit_code))
    console = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", result.output or "")
    console = re.sub(r"[\s─-╿]", "", console)
    sources = {"console": console}
    for i, r in enumerate(sink.records):
        if r.levelno >= logging.INFO:
            sources[f"log{i}:{r.levelname}:{r.filename}:{r.lineno}"] = r.getMessage()
    held = _holding(sources, middles)
    assert not held, held


def test_seg_plugin_list_console_root_from_import(
    tmp_path: Path, monkeypatch, site: Path, sink: _Sink
):
    """The root-from-import shape through ``ash plugin list --config``, no
    ``--debug``. The console is read with whitespace and box-drawing
    characters removed, so a wrapped name is still found."""
    from typer.testing import CliRunner

    from automated_security_helper.cli.main import app

    files, value = LEAFY["root-from-import"]
    _plant(site, files)
    monkeypatch.setenv("ASH_SEG_LEAF", value)
    cfg = _config_file(tmp_path / "seg-cli" / "cfg.yaml", ["${ASH_SEG_LEAF}", LIT])
    project = tmp_path / "seg-proj"
    project.mkdir()
    monkeypatch.chdir(project)
    result = CliRunner().invoke(app, ["plugin", "list", "--config", str(cfg)])
    if result.exit_code != 3:
        raise RuntimeError(("premise: the listing was refused", result.exit_code))
    console = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", result.output or "")
    console = re.sub(r"[\s\u2500-\u257f]", "", console)
    sources = {"console": console}
    for i, r in enumerate(sink.records):
        if r.levelno >= logging.INFO:
            sources[f"log{i}:{r.levelname}:{r.filename}:{r.lineno}"] = r.getMessage()
    held = _holding(sources, (ROOT_LEAF,))
    assert not held, held


HYPHEN_TOP = T.replace("_", "-")
VERSION_CALL = (
    f'import importlib.metadata\nimportlib.metadata.version("{HYPHEN_TOP}")\n'
)


@pytest.mark.parametrize("shape", ["own-body", "literal-importer"])
def test_seg_hyphen_spelling_of_the_top_level(
    tmp_path: Path, monkeypatch, site: Path, sink: _Sink, shape: str
):
    """The PEP 503 spelling of the masked value's top level is a needle: a
    package body asking importlib.metadata for its own distribution quotes
    the hyphen name ("No package metadata was found for top-ash-plugins"),
    which no dotted, slash or backslash form matches."""
    files = {f"{T}/__init__.py": VERSION_CALL}
    if shape == "literal-importer":
        files[f"{LIT}/__init__.py"] = f"import {T}\n"
        entries_tail = [LIT]
    else:
        entries_tail = []
    _plant(site, files)
    monkeypatch.setenv("ASH_SEG_HYP", P)
    names, record, shown, sources = _engine_load(
        tmp_path, ["${ASH_SEG_HYP}", *entries_tail], sink
    )
    if P not in record:
        raise RuntimeError(("premise: the masked entry failed", sorted(record)))
    if shape == "literal-importer" and LIT not in record:
        raise RuntimeError(("premise: the literal importer failed", sorted(record)))
    if "No package metadata was found for" not in sources["record-texts"]:
        raise RuntimeError(("premise: the metadata lookup raised", sources))
    held = _holding(sources, (HYPHEN_TOP,))
    assert not held, held


LEAF6 = "kqleaf"
SHORT_LEAF_SPELLINGS: Dict[str, str] = {
    # A 4-7-character leaf is under the anywhere band, so its bare form is
    # never a needle; only the leaf's ".py" and ".cpython" file spellings
    # hide these shapes.
    "py-file": f"cannot compile {LEAF6}.py",
    "pyc-cache": f"stale cache __pycache__/{LEAF6}.cpython-314.pyc",
}


@pytest.mark.parametrize("kind", sorted(SHORT_LEAF_SPELLINGS))
def test_seg_a_short_leafs_file_spelling_hides_under_a_hidden_suffix(
    tmp_path: Path, monkeypatch, site: Path, sink: _Sink, kind: str
):
    """A three-segment value whose leaf is 4-7 characters: the hidden suffix
    S1.leaf carries the leaf's ".py" and "__pycache__" ".cpython" spellings,
    which no bare or dotted form matches (the bare leaf is under the
    anywhere band)."""
    value = f"{T}.{S1}.{LEAF6}"
    _plant(
        site,
        {
            f"{LIT}/__init__.py": RAISES_FROM_FILE,
            f"{LIT}/msg.txt": SHORT_LEAF_SPELLINGS[kind],
        },
    )
    monkeypatch.setenv("ASH_SEG_SHORT", value)
    names, record, shown, sources = _engine_load(
        tmp_path, ["${ASH_SEG_SHORT}", LIT], sink
    )
    if sorted(record) != sorted([value, LIT]):
        raise RuntimeError(("premise: both failed", sorted(record)))
    held = _holding(sources, (LEAF6,))
    assert not held, held


def test_seg_a_two_segment_short_leaf_prints_its_file_spelling(
    tmp_path: Path, monkeypatch, site: Path, sink: _Sink
):
    """Cost pin, must-not-flag: with only two segments, no suffix passes the
    anywhere band, so the short leaf's file spellings are not needles and
    "leaf.py" prints. The leaf leaks exactly where no longer suffix holding
    it hides -- the documented bound, pinned so a widening is a decision."""
    value = f"{T}.{LEAF6}"
    _plant(
        site,
        {
            f"{LIT}/__init__.py": RAISES_FROM_FILE,
            f"{LIT}/msg.txt": SHORT_LEAF_SPELLINGS["py-file"],
        },
    )
    monkeypatch.setenv("ASH_SEG_SHORT2", value)
    names, record, shown, sources = _engine_load(
        tmp_path, ["${ASH_SEG_SHORT2}", LIT], sink
    )
    if sorted(record) != sorted([value, LIT]):
        raise RuntimeError(("premise: both failed", sorted(record)))
    held = _holding(sources, (LEAF6,))
    assert held, sources["record-texts"][:300]


ASH_FRAME = "automated_security_helper/plugins/loader.py"
ASH_WORD_SHAPES: Dict[str, Tuple[str, str]] = {
    # the masked value, the ASH-printed text that must survive in DEBUG.
    "leaf-inside-ash-word": (f"{T}.security", ASH_FRAME),
    "segment-py-is-ash-file": (f"{T}.loader.{S2}", "plugins/loader.py"),
}


@pytest.mark.parametrize("shape", sorted(ASH_WORD_SHAPES))
def test_seg_ash_frame_stays_readable(
    tmp_path: Path, monkeypatch, site: Path, sink: _Sink, shape: str
):
    """Must-not-flag: a masked segment that occurs INSIDE a word ASH's own
    frames print ("security" inside automated_security_helper), or whose
    ".py" spelling is an ASH file of its own ("loader" making "loader.py"),
    must not blank the frame: the needle bounds exempt by containment and
    emit file spellings for the last segment only."""
    value, must_survive = ASH_WORD_SHAPES[shape]
    monkeypatch.setenv("ASH_SEG_ASHW", value)
    names, record, shown, sources = _engine_load(tmp_path, ["${ASH_SEG_ASHW}"], sink)
    if sorted(record) != [value]:
        raise RuntimeError(("premise: the entry failed", sorted(record)))
    debug = "\n".join(
        b for w, b in sources.items() if ":DEBUG:" in w and TRACEBACK in b
    )
    if not debug:
        raise RuntimeError("premise: the DEBUG traceback was logged")
    assert must_survive in debug, debug[-500:]
    # The control: a plain-leaf value with no ASH-word collision keeps the
    # same frame readable too, so the assertion above measures the needle
    # set, not the traceback's shape.
    held = _holding(sources, (T,))
    assert not held, held


# --- D: over-redaction controls ----------------------------------------------


def test_seg_namespace_root_stays_readable(
    tmp_path: Path, monkeypatch, site: Path, sink: _Sink
):
    """Must-not-flag: an env-read three-segment entry under the namespace
    root, root missing: "No module named 'ash_plugins'" stays readable, the
    rest of the value is hidden."""
    if importlib.util.find_spec("ash_plugins") is not None:
        raise RuntimeError("premise: no ash_plugins package is importable")
    value = "ash_plugins.kqrootmidq.kqrootleafq"
    monkeypatch.setenv("ASH_SEG_ROOT", value)
    names, record, shown, sources = _engine_load(tmp_path, ["${ASH_SEG_ROOT}"], sink)
    if sorted(record) != [value]:
        raise RuntimeError(("premise: the entry failed", sorted(record)))
    assert "No module named 'ash_plugins'" in sources["record-texts"], sources[
        "record-texts"
    ][:300]
    held = _holding(sources, ("kqrootmidq", "kqrootleafq"))
    assert not held, held


FIXED_WORDS = {
    "refusal": (
        "ash_plugin_modules names",
        "which failed to import",
        "Nothing was scanned",
        "--config-overrides",
        "--ash-plugin-modules",
        "ASH_PLUGIN_MODULES",
    ),
    "WARNING": ("Failed to import plugin module",),
    "INFO": ("Importing additional plugin module",),
    "DEBUG": (
        "Plugin module import failure traceback (redacted)",
        "automated_security_helper/plugins/loader.py",
        "importlib",
    ),
}


def test_seg_ash_fixed_words_stay_readable(
    tmp_path: Path, monkeypatch, site: Path, sink: _Sink
):
    """Must-not-flag: with every needle of a three-segment env value in play
    (the slash spelling cell's shape), ASH's own words on each surface stay."""
    _plant(site, _spelling_files("slash", site))
    monkeypatch.setenv("ASH_SEG_ONE", P)
    names, record, shown, sources = _engine_load(
        tmp_path, ["${ASH_SEG_ONE}", LIT], sink
    )
    if sorted(record) != [LIT]:
        raise RuntimeError(("premise: only the literal module failed", sorted(record)))
    missing = {}
    for where, words in FIXED_WORDS.items():
        if where == "refusal":
            bodies = [sources["refusal"]]
        else:
            bodies = [b for w, b in sources.items() if f":{where}:" in w]
        text = "\n".join(bodies)
        lost = [word for word in words if word not in text]
        if lost:
            missing[where] = lost
    assert not missing, missing


OPT_IN_WORDS = "see automated_security_helper.plugin_modules for the shipped plugins"


def test_seg_opt_in_root_stays_readable(
    tmp_path: Path, monkeypatch, site: Path, sink: _Sink
):
    """An env-read entry under ASH's opt-in plugin root (a documented place
    for shipped plugin packages): another module's text naming that root
    keeps it, as the namespace rule's own text prints it."""
    value = "automated_security_helper.plugin_modules.segoptmiss_ash_plugins"
    _plant(
        site, {f"{LIT}/__init__.py": RAISES_FROM_FILE, f"{LIT}/msg.txt": OPT_IN_WORDS}
    )
    monkeypatch.setenv("ASH_SEG_OPT", value)
    names, record, shown, sources = _engine_load(
        tmp_path, ["${ASH_SEG_OPT}", LIT], sink
    )
    if sorted(record) != sorted([value, LIT]):
        raise RuntimeError(("premise: both failed", sorted(record)))
    held = _holding(sources, ("segoptmiss_ash_plugins",))
    if held:
        raise RuntimeError(("premise: the value's own leaf is hidden", held))
    assert "automated_security_helper.plugin_modules" in record[LIT].recorded, record[
        LIT
    ].recorded[:300]


def test_seg_a_leaf_that_is_an_ash_word_stays_readable(
    tmp_path: Path, monkeypatch, site: Path, sink: _Sink
):
    """Must-not-flag: a masked value's leaf that IS a word ASH's own text
    prints (a plugin kind) is never a suffix needle: another module's
    message using the word keeps it, while the value's other forms stay
    hidden. The accepted cost of the suffix rule's word-set bound: this
    value's own leaf prints wherever a text quotes it alone."""
    value = f"{T}.{S1}.scanners"
    _plant(
        site,
        {
            f"{LIT}/__init__.py": RAISES_FROM_FILE,
            f"{LIT}/msg.txt": "the scanners table is empty",
        },
    )
    monkeypatch.setenv("ASH_SEG_WORD", value)
    names, record, shown, sources = _engine_load(
        tmp_path, ["${ASH_SEG_WORD}", LIT], sink
    )
    if sorted(record) != sorted([value, LIT]):
        raise RuntimeError(("premise: both failed", sorted(record)))
    assert "the scanners table is empty" in record[LIT].recorded, record[LIT].recorded[
        :300
    ]
    held = _holding(sources, (T, S1))
    assert not held, held


def test_seg_a_segment_inside_a_load_printed_word_stays_readable(
    tmp_path: Path, monkeypatch, site: Path, sink: _Sink
):
    """Must-not-flag: a masked value's segment spelled like PART of a word
    the load's own frames print (here "bootstrap", inside the import
    machinery's "_bootstrap" frames) is never a run needle: another module's
    message quoting the word alone keeps it. The accepted cost of the
    frame-word containment bound, documented beside the word list: this
    value's own segment prints wherever a text quotes it alone, while the
    value's other segments stay hidden."""
    value = f"{T}.bootstrap.{S2}"
    _plant(
        site,
        {
            f"{LIT}/__init__.py": RAISES_FROM_FILE,
            f"{LIT}/msg.txt": "the loader bootstrap step finished",
        },
    )
    monkeypatch.setenv("ASH_SEG_BOOT", value)
    names, record, shown, sources = _engine_load(
        tmp_path, ["${ASH_SEG_BOOT}", LIT], sink
    )
    if sorted(record) != sorted([value, LIT]):
        raise RuntimeError(("premise: both failed", sorted(record)))
    assert "the loader bootstrap step finished" in record[LIT].recorded, record[
        LIT
    ].recorded[:300]
    held = _holding(sources, (T, S2))
    assert not held, held


def test_seg_floor_keeps_a_short_refused_top_level_readable(
    tmp_path: Path, monkeypatch, site: Path, sink: _Sink
):
    """The word-band floor, documented: a piece the namespace check refuses
    has a 2-character top level; a literal module importing it quotes "No
    module named 'ab'", which stays readable (the floor), while the piece's
    full forms are hidden."""
    piece = "ab.kqflrsegm"
    _plant(
        site,
        {f"{PAIR_OTHER}/__init__.py": "", f"{LIT}/__init__.py": f"import {piece}\n"},
    )
    monkeypatch.setenv("ASH_SEG_FLR", f"{piece},{PAIR_OTHER}")
    names, record, shown, sources = _engine_load(
        tmp_path, ["${ASH_SEG_FLR}", LIT], sink
    )
    if sorted(record) != [LIT] or piece not in names:
        raise RuntimeError(("premise: only the literal failed", sorted(record), names))
    assert "No module named 'ab'" in record[LIT].recorded, record[LIT].recorded[:300]
    held = _holding(sources, ("kqflrsegm",))
    assert not held, held


def test_seg_literal_label_sharing_a_masked_prefix(
    tmp_path: Path, monkeypatch, site: Path, sink: _Sink
):
    """Observation pin: a literal entry whose top level equals a masked
    entry's top level is named in clear by its label, while its own error
    text masks that same top level. Pins the measured state."""
    other = f"{T}.kqotherzz"
    _plant(site, {f"{T}/__init__.py": "", f"{T}/{S1}/__init__.py": ""})
    monkeypatch.setenv("ASH_SEG_PFX", f"{T}.{S1}")
    names, record, shown, sources = _engine_load(
        tmp_path, ["${ASH_SEG_PFX}", other], sink
    )
    if sorted(record) != [other] or (shown or {}).get(other) != other:
        raise RuntimeError(
            ("premise: the literal failed, shown as itself", sorted(record))
        )
    warning = "".join(b for w, b in sources.items() if ":WARNING:" in w)
    facts = {
        "warning_label_names_top_in_clear": f"plugin module {other}:" in warning,
        "refusal_label_names_top_in_clear": f"'{other}'" in sources["refusal"],
        "record_masks_the_top": "<value>.kqotherzz" in record[other].recorded,
    }
    assert facts == {
        "warning_label_names_top_in_clear": True,
        "refusal_label_names_top_in_clear": True,
        "record_masks_the_top": True,
    }, facts
