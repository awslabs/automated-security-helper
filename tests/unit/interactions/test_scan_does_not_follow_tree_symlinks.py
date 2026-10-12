# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A whole ``ash scan`` over a tree whose converter inputs are symlinks to host files.

The unit tests next to each reader drive it in isolation. This one runs the real
command, in a child process, over a tree built for it, and inspects everything the run
wrote. The convert and report phases run; the scan phase is left out because no scanner
is needed to show what the converters and ``scan_set`` write.

One process boundary is replaced: ``jupyter nbconvert``. Whether nbconvert is installed
differs between machines, so the child stands in for it with a function that does what
nbconvert does -- expand the notebook argument with ``glob.glob``, read the notebook,
and write its code cells to ``<--output-dir>/<--output>.py`` -- and nothing else.
Everything ASH does around it is real.

The tree holds, beside a "host" directory with a marker string in every file:

- ``a.zip``, ``b.tar``, ``nb.ipynb``: symlinks to host files, which the scan set
  leaves out because their targets leave the tree, so no converter sees them;
- ``sub/.gitignore``: a symlink to a host file, left out of the scan set the same
  way, and whose rules are not applied;
- ``c.zip``, ``d.tar``, ``nb2.ipynb``: symlinks to the regular files below, which the
  scan set keeps and each converter refuses;
- ``ok.zip``, ``ok.tar``, ``ok.ipynb``: regular files, the positive control, two of
  them carrying members that are links or whose names leave the destination.
"""

from __future__ import annotations

import io
import json
import os
import stat
import subprocess
import sys
import tarfile
import textwrap
import zipfile
from pathlib import Path

import pytest

MARKER = "HOST-ONLY-CONTENT-e8a7"

LINK_WITH_A_BACKTICK = "tick`name.py"

#: The tree's links whose targets are outside it, as paths below the tree.
LINKS_LEAVING_THE_TREE = (
    "a.zip",
    "b.tar",
    "nb.ipynb",
    "sub/.gitignore",
    LINK_WITH_A_BACKTICK,
)

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)

# Run in the child. Only `jupyter nbconvert` is replaced; every other subprocess.run
# call goes to the real function.
DRIVER = textwrap.dedent(
    """
    import glob
    import json
    import os
    import subprocess
    import sys
    from pathlib import Path

    # The ASH the parent test imported, ahead of whatever the interpreter has
    # installed, so the child runs the code under test.
    sys.path.insert(0, os.environ["ASH_TEST_CODE_ROOT"])

    import automated_security_helper
    from automated_security_helper.plugin_modules.ash_builtin.converters import (
        jupyter_converter,
    )
    from automated_security_helper.utils import uv_tool_runner

    real_get_runner = uv_tool_runner.get_uv_tool_runner
    calls_log = Path(os.environ["ASH_TEST_NBCONVERT_CALLS"])
    Path(os.environ["ASH_TEST_IMPORTED_FROM"]).write_text(
        automated_security_helper.__file__
    )

    class Runner:
        # The real runner for everything except running nbconvert, which is done
        # here the way `nbconvert --to script` does it, and recorded.
        def __init__(self, real):
            self._real = real

        def __getattr__(self, name):
            return getattr(self._real, name)

        def is_uv_available(self):
            return True

        def run_tool(self, **kwargs):
            if kwargs.get("tool_name") != "jupyter-nbconvert":
                return self._real.run_tool(**kwargs)
            args = list(kwargs["args"])
            (pattern,) = [a for a in args if a.endswith(".ipynb")]
            (notebook_path,) = glob.glob(pattern)
            notebook = json.loads(Path(notebook_path).read_text(encoding="utf-8"))
            code = "".join(
                "".join(cell.get("source", []))
                for cell in notebook.get("cells", [])
                if cell.get("cell_type") == "code"
            )
            with calls_log.open("a", encoding="utf-8") as log:
                cwd = kwargs.get("cwd")
                record = {
                    "args": args,
                    # None stays null: str(None) is "None", a relative path that is
                    # never inside the tree, so the check below could not fail.
                    "cwd": None if cwd is None else str(cwd),
                    "notebook": notebook_path,
                    "code": code,
                }
                log.write(json.dumps(record) + "\\n")
            output = Path(
                args[args.index("--output-dir") + 1],
                args[args.index("--output") + 1] + ".py",
            )
            output.write_text(code, encoding="utf-8")
            return subprocess.CompletedProcess(args, 0, "", "")

    uv_tool_runner.get_uv_tool_runner = lambda: Runner(real_get_runner())
    jupyter_converter.JupyterConverter.validate_plugin_dependencies = (
        lambda self: True
    )

    from automated_security_helper.cli.main import app

    sys.argv = ["ash", "scan", *sys.argv[1:]]
    app()
    """
)


def notebook(code: str) -> str:
    return json.dumps(
        {
            "cells": [
                {
                    "cell_type": "code",
                    "metadata": {},
                    "execution_count": None,
                    "outputs": [],
                    "source": [code],
                }
            ],
            "metadata": {"language_info": {"name": "python"}},
            "nbformat": 4,
            "nbformat_minor": 5,
        }
    )


def tar_member(archive: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    archive.addfile(info, io.BytesIO(data))


def build(base: Path) -> tuple[Path, Path]:
    host = base / "host"
    tree = base / "tree"
    host.mkdir()
    tree.mkdir()

    (host / "nb.ipynb").write_text(notebook(f"print('{MARKER}')\n"))
    with zipfile.ZipFile(host / "a.zip", "w") as archive:
        archive.writestr("inner.py", f"X = '{MARKER}'\n")
    with tarfile.open(host / "b.tar", "w") as archive:
        tar_member(archive, "inner_tar.py", f"Y = '{MARKER}'\n".encode())
    (host / "rules").write_text(f"{MARKER}\n")
    (host / "secret.py").write_text(f"Z = '{MARKER}'\n")

    for name in ("nb.ipynb", "a.zip", "b.tar"):
        (tree / name).symlink_to(host / name)
    (tree / "sub").mkdir()
    (tree / "sub" / ".gitignore").symlink_to(host / "rules")
    # A name with a backtick, which the markdown summary has to fence around.
    (tree / LINK_WITH_A_BACKTICK).symlink_to(host / "secret.py")

    (tree / "ok.ipynb").write_text(notebook("print('in-tree notebook')\n"))
    with zipfile.ZipFile(tree / "ok.zip", "w") as archive:
        archive.writestr("ok.py", "print('in-tree zip')\n")
        link = zipfile.ZipInfo("link.py")
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(link, str(host / "secret.py"))
        archive.writestr("../escape.py", f"E = '{MARKER}'\n")
    with tarfile.open(tree / "ok.tar", "w") as archive:
        tar_member(archive, "ok_tar.py", b"print('in-tree tar')\n")
        symlink = tarfile.TarInfo("link_tar.py")
        symlink.type = tarfile.SYMTYPE
        symlink.linkname = str(host / "secret.py")
        archive.addfile(symlink)
        tar_member(archive, "../escape_tar.py", f"E = '{MARKER}'\n".encode())
    for link, target in (("c.zip", "ok.zip"), ("d.tar", "ok.tar")):
        (tree / link).symlink_to(target)
    (tree / "nb2.ipynb").symlink_to("ok.ipynb")
    (tree / ".gitignore").write_text("*.log\n")
    (tree / "app.py").write_text("print('hello')\n")
    return tree, host


@pytest.fixture(scope="module")
def scan(tmp_path_factory):
    base = tmp_path_factory.mktemp("symlinked-inputs")
    tree, host = build(base)
    output = base / "out"
    # Given relative and through a '..', as `--source-dir sub/../tree` would be. The
    # root is made absolute without folding the '..', so every scan-set path carries
    # it; only a '..' below the root may be refused.
    (base / "sub").mkdir()
    source = Path("sub") / ".." / tree.name
    env = dict(os.environ)
    # Keep the child off the network and away from the caller's terminal settings.
    env.update({"ASH_OFFLINE": "YES", "NO_COLOR": "1", "COLUMNS": "200"})
    # Where the child records each nbconvert call: outside the output directory, so
    # the output sweeps below see only what ASH wrote.
    env["ASH_TEST_NBCONVERT_CALLS"] = str(base / "nbconvert-calls.jsonl")
    import automated_security_helper

    env["ASH_TEST_CODE_ROOT"] = str(Path(automated_security_helper.__file__).parents[1])
    env["ASH_TEST_IMPORTED_FROM"] = str(base / "imported-from.txt")
    # `-I` keeps the child's imports to the interpreter's own site-packages, which is
    # the ASH under test when the suite runs from an installed checkout, as CI does.
    completed = subprocess.run(  # nosec B603 - fixed argv, the test's own interpreter
        [
            sys.executable,
            "-I",
            "-c",
            DRIVER,
            "--source-dir",
            str(source),
            "--output-dir",
            str(output),
            "--mode",
            "local",
            "--phases",
            "convert",
            "--phases",
            "report",
            "--no-progress",
            "--no-fail-on-findings",
        ],
        capture_output=True,
        text=True,
        timeout=600,
        env=env,
        cwd=base,
    )
    # A precondition of every test below rather than a test of its own: a scan that
    # did not finish leaves nothing to inspect.
    assert completed.returncode == 0, (
        completed.stdout[-4000:] + completed.stderr[-4000:]
    )
    assert (output / "ash.log").is_file()
    assert (output / "ash_aggregated_results.json").is_file()
    # Kept beside the output directory, so the output sweeps below see only ASH's.
    (base / "console.txt").write_text(completed.stdout, encoding="utf-8")
    return tree, host, output


def test_the_child_ran_the_code_under_test(scan):
    import automated_security_helper

    _, _, output = scan
    imported = Path((output.parent / "imported-from.txt").read_text())
    assert imported == Path(automated_security_helper.__file__)


def test_nbconvert_ran_outside_the_tree_on_a_copy(scan):
    """The default route (uv tool run) was taken, in a directory outside the tree."""
    tree, _, output = scan
    calls = [
        json.loads(line)
        for line in (output.parent / "nbconvert-calls.jsonl").read_text().splitlines()
    ]
    assert len(calls) == 1, calls  # ok.ipynb; nb.ipynb was refused
    (call,) = calls
    # A copy of ok.ipynb, under the fixed name nbconvert is given.
    assert Path(call["notebook"]).name == "notebook.ipynb"
    assert call["code"] == "print('in-tree notebook')\n"
    assert call["cwd"] is not None, "nbconvert inherited ASH's working directory"
    for path in (call["cwd"], call["notebook"]):
        assert not Path(path).resolve().is_relative_to(tree.resolve()), path


def test_no_host_content_reaches_the_output_directory(scan):
    """Nothing under output_dir, ash.log included, holds the host files' marker."""
    tree, host, output = scan
    holding_marker = [
        str(path.relative_to(output))
        for path in output.rglob("*")
        if path.is_file()
        and not path.is_symlink()
        and MARKER.encode() in path.read_bytes()
    ]
    assert holding_marker == []
    assert MARKER not in (output / "ash.log").read_text()
    # Nor any link, wherever it points: copying the output directory, as an artifact
    # upload does, would follow it.
    assert [str(p) for p in output.rglob("*") if p.is_symlink()] == []
    for directory in (tree.parent, tree, host):
        assert not (directory / "escape.py").exists()
        assert not (directory / "escape_tar.py").exists()


def test_each_refused_input_is_named_in_one_warning(scan):
    _, _, output = scan
    warnings = [
        line.split("\t", 3)[-1].strip()
        for line in (output / "ash.log").read_text().splitlines()
        if "\tWARNING\t" in line and "Skipped" in line
    ]
    member = "Skipped member '{}' of archive '{}': {}"
    assert sorted(warnings) == sorted(
        [
            "Skipped converter input 'c.zip': it is a symbolic link",
            "Skipped converter input 'd.tar': it is a symbolic link",
            "Skipped converter input 'nb2.ipynb': it is a symbolic link",
            (
                "Skipped ignore file 'sub/.gitignore': it is a symbolic link, so its "
                "rules were not applied"
            ),
            member.format("link.py", "ok.zip", "it is a symbolic or hard link"),
            member.format(
                "../escape.py", "ok.zip", "its path contains a '..' component"
            ),
            member.format("link_tar.py", "ok.tar", "it is a symbolic or hard link"),
            member.format(
                "../escape_tar.py", "ok.tar", "its path contains a '..' component"
            ),
        ]
    )


def test_each_link_leaving_the_tree_is_named_in_one_warning(scan):
    """The scan set leaves them out, so no converter or scanner is given them."""
    _, _, output = scan
    warnings = [
        line.split("\t", 3)[-1].strip()
        for line in (output / "ash.log").read_text().splitlines()
        if "\tWARNING\t" in line and "Not scanning" in line
    ]
    assert sorted(warnings) == sorted(
        f"Not scanning {name!r}: link leaves the scanned tree"
        for name in LINKS_LEAVING_THE_TREE
    )


def test_links_leaving_the_tree_are_listed_as_inputs_not_scanned(scan):
    """In the results, both summaries and the console, escaped as the others are."""
    from automated_security_helper.utils.display_text import (
        escape_controls,
        markdown_code_span,
    )

    _, _, output = scan
    results = json.loads((output / "ash_aggregated_results.json").read_text())
    assert results["metadata"]["inputs_not_scanned"] == [
        {"path": name, "reason": "link leaves the scanned tree"}
        for name in sorted(LINKS_LEAVING_THE_TREE)
    ]

    markdown = (output / "reports" / "ash.summary.md").read_text()
    text = (output / "reports" / "ash.summary.txt").read_text()
    console = (output.parent / "console.txt").read_text()
    assert "### Inputs not scanned" in markdown
    assert "INPUTS NOT SCANNED" in text
    for name in LINKS_LEAVING_THE_TREE:
        reason = "link leaves the scanned tree"
        assert f"- **ASH**: {markdown_code_span(name)}: {reason}" in markdown
        assert f"- ASH: {escape_controls(name)}: {reason}" in text
        assert f"Not scanned: ASH did not scan {escape_controls(name)}: {reason}" in (
            " ".join(console.split())
        )


def test_refused_inputs_are_recorded_in_the_results(scan):
    _, _, output = scan
    results = json.loads((output / "ash_aggregated_results.json").read_text())
    rows = results["converter_results"]

    def refused(name):
        return sorted(
            (r["path"], r["member"], r["reason"]) for r in rows[name]["refused_inputs"]
        )

    assert refused("archive") == sorted(
        [
            ("c.zip", None, "it is a symbolic link"),
            ("d.tar", None, "it is a symbolic link"),
            ("ok.zip", "link.py", "it is a symbolic or hard link"),
            ("ok.zip", "../escape.py", "its path contains a '..' component"),
            ("ok.tar", "link_tar.py", "it is a symbolic or hard link"),
            ("ok.tar", "../escape_tar.py", "its path contains a '..' component"),
        ]
    )
    assert refused("jupyter") == [("nb2.ipynb", None, "it is a symbolic link")]
    # A refusal is not a converter failure: the gate for incomplete conversion is
    # about converters that did not run.
    assert rows["archive"]["failure"] is None
    assert rows["jupyter"]["failure"] is None
    report = (output / "ash-ignore-report.txt").read_text()
    assert (
        "######### SKIPPED: ${SOURCE_DIR}/sub/.gitignore: it is a symbolic link "
        "#########"
    ) in report


def test_regular_inputs_still_convert(scan):
    """The positive control: in-tree inputs convert, byte for byte."""
    _, _, output = scan
    converted = output / "converted"
    by_name = {
        path.name: path.read_text() for path in converted.rglob("*") if path.is_file()
    }
    assert by_name.pop("ok.py") == "print('in-tree zip')\n"
    assert by_name.pop("ok_tar.py") == "print('in-tree tar')\n"
    (notebook_name,) = [n for n in by_name if n.endswith("ok__ipynb-converted.py")]
    assert by_name.pop(notebook_name) == "print('in-tree notebook')\n"
    assert by_name == {}, "nothing else was converted"
