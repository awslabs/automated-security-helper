"""The container and Nix runtime snapshots record what the code under test prints.

tests/conftest.py deselects the modules in runtime/ except on the CI legs that have a
container runtime or Nix, so the default tier never compares their snapshots. A
change to what a scan prints is caught by the in-process snapshots of the same scans
(test_snapshot_container_exit_codes.py and test_snapshot_container_nix.py), and
regenerating those left the runtime copies on the old text, which only the runtime
legs then reported, on every run.

Two things are pinned here, in the default tier:

* what the host prints for a scan with actionable findings, from the first line a
  runtime snapshot keeps to the verdict line, is the same in each runtime snapshot as
  in the in-process snapshot of the same mode. The runtime Container snapshot keeps
  the host's output from the "ASH Scan Completed" banner, so the in-process one is
  read from there; the Nix snapshot keeps all of it. The verdict line is left out: it
  counts the findings, and the two scans scan different fixtures;
* each scan a runtime module runs is a spelling that prints no deprecation line. The
  Nix snapshot records the whole of stderr, and a spelling that moved puts its line
  there. The scan runs with no ./src, which the engine refuses after every
  deprecation line it can print and before it builds, enters or scans anything. Three
  old spellings run the same way as a control, so the check cannot read as clean
  because it stopped looking.

The runtime modules are imported for the scans they run. That works here and not
outside tests/snapshot/, because one marker they carry, snapshot_masking, is
registered by tests/snapshot/conftest.py, and pytest.ini turns an unregistered marker
into an error.
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR
from tests.snapshot.container.runtime.test_snapshot_container_nix_runtime import (
    NIX_SCAN,
)
from tests.snapshot.container.runtime.test_snapshot_container_runtime import (
    CONTAINER_SCAN,
    FIXTURE_SCAN,
)

pytestmark = pytest.mark.unit

HERE = Path(__file__).resolve().parent
RUNTIME_SNAPSHOTS = HERE / "runtime" / "__snapshots__"
IN_PROCESS_SNAPSHOTS = HERE / "__snapshots__"

#: The two prefixes a deprecation line starts with (cli/scan_deprecation.py and
#: cli/deprecation.py).
DEPRECATION_PREFIXES = ("Deprecated:", "DeprecationWarning:")

#: What the engine says about the ./src these scans name, which the test never makes.
NO_SOURCE_DIRECTORY = "Source directory does not exist: src"

#: The first line of the block a scan with findings ends with, and how the line after
#: it, the verdict, starts.
BANNER = "=== ASH Scan Completed"
VERDICT = "ERROR ("


def _entry(path: Path, name: str) -> str:
    """What syrupy stored for the test *name* in the amber file *path*."""
    text = path.read_text(encoding="utf-8")
    header = f"# name: {name}\n"
    assert header in text, f"{path.name} records no {name}"
    start = text.index(header) + len(header)
    return text[start : text.index("\n# ---", start)]


def _text_field(path: Path, name: str, field: str) -> List[str]:
    """The lines of the text *field* of *name*'s entry in *path*, dedented."""
    lines = _entry(path, name).splitlines()
    opener = f"    '{field}': '''"
    assert opener in lines, f"{path.name}::{name} holds no {field} text"
    start = lines.index(opener) + 1
    end = lines.index("    ''',", start)
    return textwrap.dedent("\n".join(lines[start:end])).splitlines()


def _until_the_verdict(lines: List[str], start: int = 0) -> List[str]:
    """*lines* from *start* up to the verdict line, which is left out."""
    ends = [
        index
        for index in range(start, len(lines))
        if lines[index].lstrip().startswith(VERDICT)
    ]
    assert ends, "the output has no verdict line after its first line"
    return lines[start : ends[0]]


@pytest.mark.parametrize(
    (
        "runtime",
        "runtime_name",
        "runtime_field",
        "in_process",
        "in_process_name",
        "in_process_starts_at_the_banner",
    ),
    [
        pytest.param(
            RUNTIME_SNAPSHOTS / "test_snapshot_container_runtime.ambr",
            "test_container_scan_of_the_fixture",
            "host_output_after_container",
            IN_PROCESS_SNAPSHOTS / "test_snapshot_container_exit_codes.ambr",
            "test_host_recomputes_the_verdict",
            True,
            id="container",
        ),
        pytest.param(
            RUNTIME_SNAPSHOTS / "test_snapshot_container_nix_runtime.ambr",
            "test_nix_scan_of_the_fixture",
            "stdout",
            IN_PROCESS_SNAPSHOTS / "test_snapshot_container_nix.ambr",
            "test_shell_exit_with_results",
            False,
            id="nix",
        ),
    ],
)
def test_a_runtime_snapshot_prints_what_the_in_process_one_does(
    runtime,
    runtime_name,
    runtime_field,
    in_process,
    in_process_name,
    in_process_starts_at_the_banner,
):
    printed = _text_field(in_process, in_process_name, "stdout")
    start = 0
    if in_process_starts_at_the_banner:
        banners = [index for index, line in enumerate(printed) if BANNER in line]
        assert len(banners) == 1, f"{in_process_name} has {len(banners)} banners"
        start = banners[0]
    expected = _until_the_verdict(printed, start)
    # Two blocks that both lost their lines would compare equal.
    assert "To investigate..." in expected and "=== ASH Exit Codes ===" in expected

    kept = _text_field(runtime, runtime_name, runtime_field)
    assert _until_the_verdict(kept) == expected


def _refused_for_the_missing_directory(run_cli, args: List[str]) -> dict:
    """Run *args* with no ./src; the answer has been through every deprecation line."""
    result = run_cli(args)
    assert result["exit_code"] == ASH_EXIT_USAGE_ERROR, result
    assert NO_SOURCE_DIRECTORY in result["stderr"], result["stderr"]
    return result


def _deprecation_lines(stderr: str) -> List[str]:
    return [
        line for line in stderr.splitlines() if line.startswith(DEPRECATION_PREFIXES)
    ]


@pytest.mark.parametrize(
    "args",
    [
        pytest.param(CONTAINER_SCAN, id="container-mode"),
        pytest.param(FIXTURE_SCAN, id="container-mode-of-the-fixture"),
        pytest.param(NIX_SCAN, id="nix-mode-of-the-fixture"),
    ],
)
def test_a_scan_a_runtime_snapshot_runs_prints_no_deprecation_line(args, run_cli):
    result = _refused_for_the_missing_directory(run_cli, args)

    assert _deprecation_lines(result["stderr"]) == [], result["stderr"]
    assert "deprecat" not in (result["stdout"] + result["stderr"]).lower(), result


#: The mode's own arguments, for the three old spellings below.
_NIX_ARGUMENTS = ["--mode", "nix", "--no-progress", "--output-dir", "out"]


@pytest.mark.parametrize(
    ("args", "says"),
    [
        pytest.param(
            ["scan", *_NIX_ARGUMENTS, "--source-dir", "src"],
            "`ash scan` without a subject is deprecated",
            id="scan-without-a-subject",
        ),
        pytest.param(
            ["scan", "fs", *_NIX_ARGUMENTS, "--source-dir", "src"],
            "`--source-dir` is deprecated",
            id="source-dir",
        ),
        pytest.param(
            ["scan", "fs", "src", *_NIX_ARGUMENTS, "--scanners", "bandit"],
            "--scanners (and ASH_SCANNERS) is deprecated",
            id="scanners",
        ),
    ],
)
def test_the_check_sees_the_old_spellings_the_runtime_scans_left(args, says, run_cli):
    # The control for the test above: each old spelling is flagged the same way, so a
    # clean answer there is not the check having stopped short of the line.
    result = _refused_for_the_missing_directory(run_cli, args)

    lines = _deprecation_lines(result["stderr"])
    assert len(lines) == 1 and says in lines[0], result["stderr"]
