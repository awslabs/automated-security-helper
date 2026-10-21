# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""`ash inspect findings` reads a finding's source only from a regular file in the scan.

A finding the results give no snippet for has its lines read from disk when its
detail view opens. The file is named by the results, so by a scanner's output and
the scanned repository. The TUI reads it only from below the scanned directory, so
it never opens a FIFO or a device, and it does not read a symlink or a "../"
path that leads outside the scanned tree.

The scanned directory is the one ASH's output layout names, ``<root>/.ash/ash_output``
holding the results. The source is read only from a regular file below it, through
utils/scanned_tree.py (no FIFO, device or socket; a link only when it stays inside),
and only so many bytes. Otherwise the detail view says "(source not shown)".

The cells that can hang or exhaust memory on code without that bound run the
command in a child process with a data limit and a timeout. The child imports this
checkout (PYTHONPATH) and prints the module file it loaded, so a result from another
install cannot pass for this one.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from tests.utils.helpers import importing_this_checkout
from rich.console import Console

pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="FIFOs, /dev/zero and a data limit are POSIX's",
)

CHECKOUT = Path(__file__).resolve().parents[4]
RESULTS = "ash_aggregated_results.json"
OUTSIDE_MARKER = "OUTSIDE-THE-SCANNED-TREE"
#: Lines of the regular in-root file.
SOURCE = "".join(f"value_{n} = {n}\n" for n in range(1, 10))
#: How long the child may take: importing Textual is most of it.
CHILD_TIMEOUT = 60

#: Runs `ash inspect findings` on the results under argv[1], with the app's run
#: replaced by opening the first finding's detail view. Prints the module file it
#: imported, the finding's snippet afterwards, the most memory the open traced, and
#: the bytes it read (Linux's /proc/self/io rchar; None elsewhere).
CHILD = """
import json, os, resource, sys, tracemalloc
from pathlib import Path

limit = 1 << 30
resource.setrlimit(resource.RLIMIT_DATA, (limit, limit))

import automated_security_helper
from automated_security_helper.cli.inspect import inspect_findings_app as tui

root = Path(sys.argv[1])
seen = {"file": automated_security_helper.__file__}


def bytes_read():
    if not os.path.exists("/proc/self/io"):
        return None
    with open("/proc/self/io", encoding="ascii") as io:
        fields = dict(line.split(": ") for line in io.read().splitlines())
    return int(fields["rchar"])


class Table:
    row_count = 1
    cursor_row = 0


def run(app):
    app.query_one = lambda *args, **kwargs: Table()
    app.push_screen = lambda *args, **kwargs: None
    finding = app.filtered_findings[0]
    before = bytes_read()
    tracemalloc.start()
    app.action_view_selected()
    seen["peak"] = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    after = bytes_read()
    seen["read"] = None if before is None else after - before
    seen["snippet"] = finding.get("code_snippet")


tui.FindingsExplorerApp.run = run
tui.findings_command(
    output_dir=root, report_file=sys.argv[2], config=root / ".ash.yaml"
)
print(json.dumps(seen))
"""


def _results(uri: str, line: int) -> dict:
    """Results holding one finding at *uri*:*line*, with no snippet."""
    location = {
        "physicalLocation": {
            "artifactLocation": {"uri": uri},
            "region": {"startLine": line},
        }
    }
    result = {
        "ruleId": "R1",
        "message": {"text": "a finding with no snippet"},
        "level": "warning",
        "locations": [location],
        "properties": {"scanner_details": {"tool_name": "probe"}},
    }
    run = {"tool": {"driver": {"name": "probe"}}, "results": [result]}
    return {"sarif": {"version": "2.1.0", "runs": [run]}}


def _tree(tmp_path: Path) -> tuple[Path, Path]:
    """A scanned tree with src/app.py, and a file beside it, outside it."""
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "src" / "app.py").write_text(SOURCE, encoding="utf-8")
    outside = tmp_path / "outside" / "secret.py"
    outside.parent.mkdir()
    outside.write_text(f"{OUTSIDE_MARKER} = 1\n" * 9, encoding="utf-8")
    return root, outside


def _plant(cell: str, root: Path, outside: Path) -> str:
    """Make what *cell* names in the tree, and return the uri a finding gives it."""
    src = root / "src"
    if cell == "fifo":
        os.mkfifo(src / "pipe.py")
        return "src/pipe.py"
    if cell == "in-root-link-to-a-fifo":
        os.mkfifo(src / "pipe.py")
        (src / "alias.py").symlink_to("pipe.py")
        return "src/alias.py"
    if cell == "dev-zero":
        return "/dev/zero"
    if cell == "link-out-of-the-root":
        (src / "link.py").symlink_to(outside)
        return "src/link.py"
    if cell == "dotdot-out-of-the-root":
        return "../outside/secret.py"
    if cell == "absolute-path-outside-the-root":
        return str(outside)
    if cell == "one-huge-line":
        # A sparse gigabyte with no newline: the line never ends.
        with open(src / "bundle.min.js", "wb") as handle:
            handle.truncate(1 << 30)
        return "src/bundle.min.js"
    if cell == "regular-file-in-the-root":
        return "src/app.py"
    if cell == "in-root-link-to-a-regular-file":
        (src / "alias.py").symlink_to("app.py")
        return "src/alias.py"
    raise AssertionError(cell)


def _open_detail_in_child(root: Path, uri: str, line: int) -> dict:
    output = root / ".ash" / "ash_output"
    output.mkdir(parents=True)
    (output / RESULTS).write_text(json.dumps(_results(uri, line)), encoding="utf-8")
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [str(CHECKOUT)] + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else [])
    )
    child = subprocess.Popen(  # nosec B603 - this interpreter, fixed arguments
        [sys.executable, "-c", importing_this_checkout(CHILD), str(root), RESULTS],
        cwd=root,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        stdout, stderr = child.communicate(timeout=CHILD_TIMEOUT)
    except subprocess.TimeoutExpired:
        child.kill()
        child.communicate()
        pytest.fail(f"opening the detail view of {uri} did not end in {CHILD_TIMEOUT}s")
    assert child.returncode == 0, stderr
    seen = json.loads(stdout.strip().splitlines()[-1])
    # The child imported this checkout, not another install.
    assert Path(seen["file"]).resolve().is_relative_to(CHECKOUT), seen["file"]
    return seen


#: Cells whose file is not read: the detail view shows "(source not shown)".
REFUSED = [
    "fifo",
    "in-root-link-to-a-fifo",
    "dev-zero",
    "link-out-of-the-root",
    "dotdot-out-of-the-root",
    "absolute-path-outside-the-root",
]


@pytest.mark.parametrize("cell", REFUSED)
def test_a_file_that_is_not_a_regular_file_in_the_scan_is_not_read(tmp_path, cell):
    root, outside = _tree(tmp_path)
    uri = _plant(cell, root, outside)

    seen = _open_detail_in_child(root, uri, 3)

    assert seen["snippet"] is None, seen
    # Not read at all: the open traced next to no memory, and read next to nothing
    # (the bytes the /proc/self/io reads themselves take).
    assert seen["peak"] < 1 << 20, seen
    assert seen["read"] is None or seen["read"] < 1 << 16, seen


@pytest.mark.parametrize(
    "cell", ["regular-file-in-the-root", "in-root-link-to-a-regular-file"]
)
def test_a_regular_file_in_the_scan_shows_the_lines_around_the_finding(tmp_path, cell):
    root, outside = _tree(tmp_path)
    uri = _plant(cell, root, outside)

    seen = _open_detail_in_child(root, uri, 3)

    snippet = seen["snippet"]
    assert snippet is not None, seen
    assert "→ 3: value_3 = 3" in snippet, snippet
    assert "  1: value_1 = 1" in snippet and "  8: value_8 = 8" in snippet, snippet
    assert "  9: value_9 = 9" not in snippet, snippet


def test_a_line_that_never_ends_is_read_only_so_far(tmp_path):
    root, outside = _tree(tmp_path)
    uri = _plant("one-huge-line", root, outside)

    seen = _open_detail_in_child(root, uri, 1)

    from automated_security_helper.cli.inspect.inspect_findings_app import (
        SNIPPET_LINE_CHARS,
        SOURCE_READ_LIMIT,
    )

    snippet = seen["snippet"]
    assert snippet is not None and snippet.startswith("→ 1: "), seen
    # One line's head, not the gigabyte: in memory, and in what was read.
    assert len(snippet) <= SNIPPET_LINE_CHARS + 16, len(snippet)
    assert seen["peak"] < 1 << 20, seen["peak"]
    assert seen["read"] is None or seen["read"] <= SOURCE_READ_LIMIT + (1 << 16), seen[
        "read"
    ]


def _drawn_text(app) -> str:
    """The text the screen draws now, as Textual's screenshot gets it."""
    width, height = app.size
    console = Console(
        width=width,
        height=height,
        file=io.StringIO(),
        force_terminal=True,
        color_system=None,
        record=True,
        legacy_windows=False,
        safe_box=False,
    )
    console.print(
        app.screen._compositor.render_update(
            full=True, screen_stack=app._background_screens
        )
    )
    return console.export_text()


def test_a_hard_link_in_the_tree_is_read_as_an_in_tree_file(tmp_path):
    """A hard link inside the scanned tree is the file it names, as
    it is for the scanners, which read and report it. Only a local user who can
    already read the other name can make one, and a clone cannot."""
    from automated_security_helper.cli.inspect import inspect_findings_app as tui

    root, outside = _tree(tmp_path)
    os.link(outside, root / "src" / "linked.py")

    excerpt = tui._source_excerpt({"file": "src/linked.py", "line": 3}, root)

    assert excerpt is not None and f"→ 3: {OUTSIDE_MARKER} = 1" in excerpt, excerpt


def test_the_help_says_where_a_findings_code_comes_from():
    """The help names each case: the results' own snippet, from anywhere; the
    file, only from results in <root>/.ash/ash_output and a regular file inside
    <root>, a hard link counting as one; and the notice otherwise."""
    from typer.testing import CliRunner

    from automated_security_helper.cli.inspect import inspect_app

    result = CliRunner().invoke(
        inspect_app, ["findings", "--help"], env={"COLUMNS": "200"}
    )

    assert result.exit_code == 0, result.output
    text = " ".join(result.output.replace("│", " ").split())
    for phrase in (
        "the code snippet the results hold, wherever the results file is",
        "only when the results file sits in <root>/.ash/ash_output",
        "only from a regular file inside <root>",
        (
            "a hard link inside the tree counts as a file in it, as it does for "
            "the scanners"
        ),
        '"(source not shown)"',
    ):
        assert phrase in text, (phrase, text)


#: The most a source read may take for a file of many short lines. Counting line
#: ends in 64 KiB chunks takes well under a second for the whole 64 MiB budget;
#: one readline per line took 18.9 s, on the UI thread, with no input taken.
MANY_LINES_BOUND_S = 2.0


@pytest.mark.parametrize(
    ("lines", "line", "shown"),
    [
        pytest.param(30_000_000, 29_999_990, True, id="the-line-within-the-budget"),
        pytest.param(40_000_000, 39_999_990, False, id="the-line-past-the-budget"),
    ],
)
def test_a_file_of_many_short_lines_is_read_in_bounded_time(
    tmp_path, lines, line, shown
):
    from automated_security_helper.cli.inspect import inspect_findings_app as tui

    root = tmp_path / "repo"
    root.mkdir()
    with open(root / "many.txt", "wb") as handle:
        handle.write(b"x\n" * lines)
    finding = {"file": "many.txt", "line": line}

    started = time.monotonic()
    excerpt = tui._source_excerpt(finding, root)
    elapsed = time.monotonic() - started

    assert elapsed < MANY_LINES_BOUND_S, elapsed
    if shown:
        assert excerpt is not None and f"→ {line}: x\n" in excerpt, excerpt
        assert excerpt.count("\n") == 11, excerpt
    else:
        assert excerpt is None, excerpt


@pytest.mark.asyncio
async def test_the_detail_view_says_the_source_is_not_shown(tmp_path):
    from automated_security_helper.cli.inspect.inspect_findings_app import (
        FindingsExplorerApp,
    )

    root, outside = _tree(tmp_path)
    finding = {
        "rule_id": "R1",
        "severity": "high",
        "scanner": "probe",
        "file": _plant("link-out-of-the-root", root, outside),
        "line": 3,
        "message": "m",
        "suppressed": False,
    }
    app = FindingsExplorerApp(
        [finding], config_path=tmp_path / ".ash.yaml", scan_root=root
    )
    async with app.run_test(size=(120, 40)) as pilot:
        for _ in range(6):
            await pilot.pause()
        await pilot.press("v")
        for _ in range(6):
            await pilot.pause()

        text = _drawn_text(app)
        assert "(source not shown)" in text, text
        assert OUTSIDE_MARKER not in text, text


@pytest.mark.parametrize(
    ("output_dir", "report", "scan_root"),
    [
        pytest.param(
            "repo", "repo/.ash/ash_output", "repo", id="the-scanned-directory"
        ),
        pytest.param(
            "repo/.ash", "repo/.ash/ash_output", "repo", id="its-dot-ash-directory"
        ),
        pytest.param(
            "repo/.ash/ash_output",
            "repo/.ash/ash_output",
            "repo",
            id="its-output-directory",
        ),
        pytest.param("results", "results", None, id="an-output-directory-elsewhere"),
    ],
)
def test_the_scan_root_is_the_directory_the_results_were_written_in(
    tmp_path, monkeypatch, output_dir, report, scan_root
):
    from automated_security_helper.cli.inspect import inspect_findings_app as tui

    (tmp_path / report).mkdir(parents=True)
    (tmp_path / report / RESULTS).write_text(
        json.dumps(_results("src/app.py", 3)), encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)

    with patch.object(tui, "FindingsExplorerApp") as app_class:
        tui.findings_command(
            output_dir=tmp_path / output_dir,
            report_file=RESULTS,
            config=tmp_path / ".ash.yaml",
        )

    expected = None if scan_root is None else (tmp_path / scan_root).absolute()
    assert app_class.call_args.kwargs["scan_root"] == expected
