"""Page claims about the scan subjects that the command line decides.

Each test follows the pattern of test_page_claims.py: ``assert_on_page`` checks that a
sentence is still on its page, and the test then runs the real command to see that the
sentence is true, so a change to either half fails here.

What is pinned:

- scale-large-repos.md: a sharded workspace scan is a usage error, with exit 5, in the
  spelling 3.9 gives a workspace scan and in the deprecated one.
- reference/exit-codes.md: where an option typed before a subcommand goes, and the
  example the page gives of one that is refused.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR
from tests.unit.docs.test_page_claims import SCALE_LARGE_REPOS, assert_on_page

pytestmark = pytest.mark.unit

#: scale-large-repos.md (What sharding does not do).
_SHARDS_DO_NOT_COMBINE_WITH_A_WORKSPACE = (
    "It does not combine with workspace scans: `ash scan workspace` takes no "
    "`--shard-index` or `--shard-count`, and the scan exits 5."
)


def _invoke(args: list[str]):
    return CliRunner().invoke(app, args, prog_name="ash")


def _one_line(text: str) -> str:
    return " ".join(text.split())


@pytest.fixture(autouse=True)
def _in_an_empty_directory(tmp_path, monkeypatch):
    """The working directory holds nothing, and no variable of the host names a file,
    a directory, a shard or a policy."""
    monkeypatch.chdir(tmp_path)
    for name in (
        "ASH_SOURCE_DIR",
        "ASH_OUTPUT_DIR",
        "ASH_CONFIG",
        "ASH_WORKSPACE",
        "ASH_WORKSPACE_CONFIG",
        "ASH_SHARD_INDEX",
        "ASH_SHARD_COUNT",
    ):
        monkeypatch.delenv(name, raising=False)


def _workspace(root: Path) -> Path:
    (root / "api").mkdir()
    path = root / "dev.code-workspace"
    path.write_text(json.dumps({"folders": [{"path": "api"}]}), encoding="utf-8")
    return path


@pytest.mark.parametrize(
    ("scan", "refusal"),
    [
        pytest.param(
            ["scan", "workspace"],
            "--shard-index",
            id="the-workspace-subject",
        ),
        pytest.param(
            ["scan", "--workspace"],
            "cannot be combined with --workspace",
            id="the-deprecated-option",
        ),
    ],
)
def test_a_sharded_workspace_scan_exits_5(tmp_path, scan, refusal):
    """scale-large-repos.md (What sharding does not do).

    ``ash scan workspace FILE --shard-index 0 --shard-count 2`` must exit 5, because the
    subject has no shard options, and so must the deprecated ``ash scan --workspace FILE``
    with the same options, which names the combination it refuses. The workspace holds a
    project that a scan would read, so an exit of 5 is the refusal and not a scan.
    """
    assert_on_page(SCALE_LARGE_REPOS, _SHARDS_DO_NOT_COMBINE_WITH_A_WORKSPACE)
    workspace = _workspace(tmp_path)

    result = _invoke(
        [*scan, str(workspace), "--shard-index", "0", "--shard-count", "2"]
    )

    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert refusal in _one_line(result.output), result.output
