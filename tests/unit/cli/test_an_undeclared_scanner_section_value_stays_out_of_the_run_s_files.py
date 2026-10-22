# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A value an undeclared scanner section reads from the environment never lands
in a file the run writes.

The config model types only the scanner sections it declares. A section for a
plugin it does not declare (a community plugin that this run does not load) is
kept as a plain mapping, so the reference walker never sees its options and the
option check leaves a section no loaded plugin reads alone. That is by design;
what must hold regardless is that the VALUE of ``${ASH_X}`` written at one of
its options reaches none of the run's output: not the aggregated results, not
any config the run writes back, not ash.log, and no reporter
output or scanner work-directory file. Each of those surfaces is asserted to
exist, and every file under the test's temporary directory is read, the input
config among them: that file holds the reference's name, and the needle the
search looks for is the value.

The scan is real and goes through the console script's entry point, disarmed
like the repo's other end-to-end scan cells: a scratch HOME, ``--offline``,
``--sandbox off``, one scanner selected, and the child's tool probes answered
without a process. The cell holds the child's tool starts at none.
"""

from __future__ import annotations

import json
import os
import subprocess  # nosec B404 - fixed argv, the checkout's own entry point
import sys
from pathlib import Path

from tests.utils.child_tool_starts import POSIX_ONLY, ChildToolStarts
from tests.utils.helpers import checkout_env

VARIABLE = "ASH_UNDECLARED_SECTION_CANARY"
CANARY = "ash-canary-6d1f-8842907"
SECTION = "community-demo-scanner"
RUN_SECONDS = 600


#: The console script's own target (``ash = ...cli.entrypoint:main``), run as the
#: script's wrapper runs it, ``sys.exit(main())``, after the child's tool probes
#: are answered (ChildToolStarts.program). ``main`` returns None and ends the
#: process through SystemExit itself, so the wrapper's ``sys.exit`` changes no exit
#: status today; it keeps the child the same as the console script if ``main`` ever
#: returns a status instead. The uv installed with ASH sits beside the interpreter,
#: which the child asks for before it searches PATH, so a stand-in uv on PATH is not
#: found: without the stubs the scan's availability check for detect-secrets ran
#: ``uv tool run detect-secrets --version`` for real.
ASH = (
    "import sys; sys.argv[0] = 'ash'; "
    "from automated_security_helper.cli.entrypoint import main; sys.exit(main())"
)


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


@POSIX_ONLY
def test_the_value_read_at_an_undeclared_section_is_in_none_of_the_runs_files(
    tmp_path,
):
    home = tmp_path / "home"
    home.mkdir()
    source = tmp_path / "src"
    (source / ".ash").mkdir(parents=True)
    (source / "app.py").write_text("print('hello')\n")
    config_file = source / ".ash" / ".ash.yaml"
    config_file.write_text(
        "project_name: undeclared-section\n"
        "scanners:\n"
        f"  {SECTION}:\n"
        "    enabled: true\n"
        "    options:\n"
        f"      ignore_unfixed: ${{{VARIABLE}}}\n",
        encoding="utf-8",
    )
    output = tmp_path / "out"
    # uv's cache and tool dirs follow the scratch HOME the unit-test guard
    # audits, so the child gets its own, inside this test's tmp_path
    # (ChildToolStarts sets them, offline, in the environment it gives). The
    # stand-ins go on last, so nothing ahead of them on PATH.
    started = ChildToolStarts(tmp_path)
    env = checkout_env(
        started.child_env(
            {
                **os.environ,
                "HOME": str(home),
                VARIABLE: CANARY,
            }
        )
    )

    done = subprocess.run(  # nosec B603 - fixed argv, disarmed environment
        [
            sys.executable,
            "-c",
            started.program(ASH),
            "scan",
            "--source-dir",
            str(source),
            "--output-dir",
            str(output),
            "--scanners",
            "detect-secrets",
            "--sandbox",
            "off",
            "--offline",
            "--no-progress",
            "--no-fail-on-findings",
        ],
        env=env,
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=RUN_SECONDS,
        check=False,
    )
    shown = (
        f"ash exited {done.returncode}\nstdout:\n{done.stdout[-3000:]}"
        f"\nstderr:\n{done.stderr[-3000:]}"
    )

    # The child answered its tool probes without starting a tool: nothing
    # reached a stand-in, and no uv left anything in its directories.
    assert started.starts() == [], shown

    results = output / "ash_aggregated_results.json"
    assert results.is_file(), shown
    logs = sorted(path for path in output.rglob("ash.log") if path.is_file())
    assert logs, shown
    # The config the run writes back lives inside the aggregated results (the
    # model embeds ash_config); the run writes no standalone config artifact,
    # so the written-config check reads the embedded one, with the key's
    # presence as its denominator rather than a filename pattern that can
    # match nothing.
    results_text = _text(results)
    embedded_config = json.loads(results_text).get("ash_config")
    assert embedded_config is not None, shown
    assert CANARY not in json.dumps(embedded_config), shown

    # The control: this section's own option was recorded, as its reference or
    # a placeholder, so absence of the value below is not absence of the
    # section.
    recorded = embedded_config["scanners"][SECTION]["options"]["ignore_unfixed"]
    assert recorded in (f"${{{VARIABLE}}}", "<value>"), (recorded, shown)

    # The surfaces the module docstring names must exist, each on its own: a
    # surface that stops being written must turn this cell red instead of
    # shrinking the set of files the search below reads.
    # A CLI scan writes ash.log only: the logger's JSON-lines format is
    # selectable from code but not from the command line, so no
    # ash.log.jsonl exists to assert. The log is asserted above (``logs``).
    reports = sorted(path for path in (output / "reports").rglob("*") if path.is_file())
    work_files = sorted(
        path
        for path in (output / "scanners" / "detect-secrets").rglob("*")
        if path.is_file()
    )
    tree = sorted(
        path.relative_to(tmp_path).as_posix()
        for path in output.rglob("*")
        if path.is_file()
    )
    missing = [
        name
        for name, found in (
            ("reports/", reports),
            ("scanners/detect-secrets/", work_files),
        )
        if not found
    ]
    assert not missing, ("no file was written under", missing, "output tree:", tree)

    # Every file under the test's temporary directory: the output directory,
    # the scratch HOME, the uv cache and tool directories, the stand-ins, the
    # source tree, and the input config itself. The config holds the
    # reference's NAME; the needle below is the VALUE, so reading it costs the
    # search nothing and keeps its breadth without a carve-out. The count is
    # the denominator, and each surface above must be among the files read.
    written = sorted(path for path in tmp_path.rglob("*") if path.is_file())
    surfaces = {results, *logs, *reports, *work_files}
    assert surfaces <= set(written), (sorted(surfaces - set(written)), shown)
    # The search spans more than the output directory: the source tree is read
    # too, so narrowing the root to a subdirectory turns this red.
    assert source / "app.py" in written, (len(written), shown)
    # The input config sits under a dot-directory: a filter that skips hidden
    # paths would drop it from the search, so it is asserted by name.
    assert config_file in written, (len(written), shown)
    leaked = [path for path in written if CANARY.encode() in path.read_bytes()]
    assert not leaked, (len(written), leaked)
    # Neither do the run's streams.
    assert CANARY not in done.stdout and CANARY not in done.stderr, shown
