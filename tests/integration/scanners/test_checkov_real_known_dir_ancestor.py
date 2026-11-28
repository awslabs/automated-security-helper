"""Real checkov: a scanned directory below a ``venv`` or ``node_modules`` is read.

checkov applies each ``--skip-path`` value with ``re.search`` and as a substring
against ``os.path.join(<walked directory>, <entry>)``, and every walked directory
starts with the absolute path of the scanned one. The values ASH gave it for
``.venv``, ``venv`` and ``node_modules`` named the directory only (``/venv/``), so
they also matched a directory above the scanned one: a target such as
``/home/me/venv/lib/python3.12/site-packages/pkg`` or ``/builds/node_modules/proj``
had every entry removed, checkov read nothing, and ASH reported the target clean.

These tests run the checkov ASH uses on a target below each such directory, so a
change in how checkov applies ``--skip-path`` shows up here and not as a clean
report. The framework is terraform alone: checkov's secrets runner matches
ancestors with a list of its own, so it would not measure ASH's values. The fixture
is the repository's Terraform fixture, whose committed checkov capture reports
CKV_AWS_20 and CKV_AWS_18 for it.

The known directories below the target stay skipped, at the first level and deeper.
"""

import sys
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    CheckovScanner,
    CheckovScannerConfig,
    CheckovScannerConfigOptions,
)

PluginContext.model_rebuild()

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        sys.platform == "win32",
        reason="ASH sends the known-directory --skip-path values on POSIX only: "
        "checkov joins the paths it walks with os.sep, so on Windows none is sent "
        "and there is no value to anchor",
    ),
]

_FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "test_data"
    / "snapshot_fixture"
    / "repo"
    / "infra"
    / "main.tf"
)

# A copy of the fixture in each known directory below the target, at the first level
# and deeper. checkov's own basename rules skip node_modules and dot-named
# directories whatever ASH passes; the venv copies are skipped only by ASH's values.
_BELOW_THE_TARGET = (
    "venv/copied.tf",
    "sub/deeper/venv/copied.tf",
    "node_modules/pkg/copied.tf",
)


def _scan(base: Path, ancestor: str) -> list[tuple[str, str]]:
    """(rule id, URI) of every result for ``base/<ancestor>/proj``, scanned as a source."""
    source = base / ancestor / "proj"
    source.mkdir(parents=True)
    fixture = _FIXTURE.read_bytes()
    (source / "main.tf").write_bytes(fixture)
    for relative in _BELOW_THE_TARGET:
        copy = source / relative
        copy.parent.mkdir(parents=True)
        copy.write_bytes(fixture)

    output = base / "out"
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(),
    )
    scanner = CheckovScanner(
        context=context,
        config=CheckovScannerConfig(
            options=CheckovScannerConfigOptions(frameworks=["terraform"])
        ),
    )
    report = scanner.scan(target=source, target_type="source")
    return [
        (result.ruleId or "", location.physicalLocation.root.artifactLocation.uri or "")
        for run in report.runs or []
        for result in run.results or []
        for location in result.locations or []
    ]


def _assert_read_and_still_skipping(found: list[tuple[str, str]]) -> None:
    # The fixture's finding: an empty report cannot pass for a scan that read it.
    assert any(
        rule == "CKV_AWS_20" and uri.endswith("main.tf") for rule, uri in found
    ), f"main.tf was not read: {found}"
    # The copies in the known directories below the target are still left out.
    copies = [uri for _, uri in found if uri.endswith("copied.tf")]
    assert copies == [], f"a known directory below the target was read: {copies}"


@pytest.mark.parametrize("ancestor", ["venv", "node_modules", ".venv"])
def test_a_target_below_a_directory_named_like_a_known_one_is_read(tmp_path, ancestor):
    _assert_read_and_still_skipping(_scan(tmp_path, ancestor))


def test_the_control_with_no_such_ancestor_is_read(tmp_path):
    # The same scan with an ordinary ancestor: it passes before the values are
    # anchored, so a red above is the ancestor and not the fixture.
    _assert_read_and_still_skipping(_scan(tmp_path, "plain"))
