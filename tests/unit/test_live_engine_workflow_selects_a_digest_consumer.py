"""The live-engine image scan selects a scanner that consumes the digest ladder.

Why this file exists
--------------------
.github/workflows/ash-image-scan-live-engine.yml scans an image by tag against a real
container engine and a real registry. It requires two things of each scan: a log line
from the digest ladder (``through the local docker engine`` while the engine holds the
image, ``through the registry (crane digest)`` once it does not) and a
``metadata.scan_source`` that names the digest the registry holds.

The scan phase resolves a tag-only reference only when a selected scanner declares the
registry read (``Fetched.IMAGE_DIGEST`` in its operational facets; see
``an_image_digest_consumer_is_selected``). syft reports no findings, so it does not
declare it. The job selected syft alone, so once that gate landed neither line was ever
written, the job failed at its first ``grep`` on every pull request, and nothing in the
unit tier read the workflow to say why.

What it pins
------------
- Each ``ash scan --image`` command in the workflow names a ``--only-scanners``
  selection that the function the scan phase asks reads as holding a digest consumer.
- Each phrase the job greps for is a line the ladder writes: the engine rung's for the
  first scan, the registry rung's for the second. The ladder runs here against an
  injected engine and registry, so nothing is pulled or asked.

Known limits
------------
The selection is read as text. A scan whose scanners come from ``--scanners``, a config
file or the environment reads as no selection and fails the first test, so the author
changes the selection here instead of getting past it. Which scanner classes count is
the gate's own walk of the classes already imported, so the test imports the two it
needs.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

import pytest
import yaml

from automated_security_helper.core.asset import ImageLocator
from automated_security_helper.utils.image_digest_resolver import resolve_image_locator
from automated_security_helper.utils.scanner_tool_types import (
    an_image_digest_consumer_is_selected,
)

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ash-image-scan-live-engine.yml"

IMAGE_TAG = "localhost:5000/ash-live-engine:ci"
DIGEST = "sha256:" + "ab" * 32


@pytest.fixture(autouse=True)
def _the_scanners_the_gate_reads_are_loaded():
    """The gate walks the scanner classes already imported; import the two it needs."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
        GrypeScanner,
    )
    from automated_security_helper.plugin_modules.ash_builtin.scanners.syft_scanner import (
        SyftScanner,
    )

    return GrypeScanner, SyftScanner


def _scan_steps() -> list[str]:
    """The run text of each workflow step that runs ``ash scan --image``.

    A backslash continuation is joined, so a command is one line.
    """
    document = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    steps = []
    for job in document["jobs"].values():
        for step in job.get("steps", []):
            run = step.get("run")
            if isinstance(run, str) and "ash scan --image" in run:
                steps.append(run.replace("\\\n", " "))
    return steps


def _command(step: str) -> str:
    """The ``ash scan --image`` line of a step."""
    (command,) = [line for line in step.splitlines() if "ash scan --image" in line]
    return command


def _selection(command: str) -> list[str]:
    """The scanner names the command's ``--only-scanners`` values name."""
    values = re.findall(r"--only-scanners[= ]+(\S+)", command)
    return [name for value in values for name in value.split(",") if name]


def _greps(step: str) -> list[str]:
    """The phrases a step ``grep -F``s the scan's log for."""
    return re.findall(r'grep -F "([^"]+)"', step)


class _Lines(logging.Handler):
    """Every message ASH_LOGGER writes: that logger does not propagate to caplog."""

    def __init__(self) -> None:
        super().__init__(level=1)
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(record.getMessage())


def _what_the_ladder_logs(engine_holds_the_image: bool) -> str:
    """The ladder's log for a tag, against a fake engine and a fake registry."""
    from automated_security_helper.utils.log import ASH_LOGGER

    def inspect(ref):
        if engine_holds_the_image:
            return DIGEST, ""
        return None, "the engine does not hold this image"

    def registry(argv, timeout):
        return 0, DIGEST + "\n"

    handler = _Lines()
    level = ASH_LOGGER.level
    ASH_LOGGER.setLevel(1)
    ASH_LOGGER.addHandler(handler)
    try:
        resolved = resolve_image_locator(
            ImageLocator(ref=IMAGE_TAG),
            offline=False,
            runner=registry,
            crane="/opt/bin/crane",
            inspector=("docker", inspect),
        )
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(level)
    assert resolved.resolved_digest == DIGEST
    return "\n".join(handler.lines)


def test_the_workflow_scans_by_tag_twice():
    steps = _scan_steps()
    assert len(steps) == 2, "one scan for the engine rung and one for the registry rung"


def test_each_scan_selects_a_scanner_that_consumes_the_digest():
    for step in _scan_steps():
        command = _command(step)
        names = _selection(command)
        assert names, f"no --only-scanners selection in: {command}"
        assert an_image_digest_consumer_is_selected(enabled_scanners=names), (
            f"{names} declares no image-digest registry read, so the scan phase "
            f"resolves no digest for: {command}"
        )


def test_the_gate_reads_syft_alone_as_no_consumer():
    # The control. The job once selected syft alone: if that read as a consumer, the
    # test above could never have gone red.
    assert an_image_digest_consumer_is_selected(enabled_scanners=["syft"]) is False
    assert an_image_digest_consumer_is_selected(enabled_scanners=["grype"]) is True


def test_the_phrases_each_scan_greps_for_are_lines_the_ladder_writes():
    engine_scan, registry_scan = _scan_steps()
    engine_phrases, registry_phrases = _greps(engine_scan), _greps(registry_scan)
    assert engine_phrases, "the engine rung's scan greps for nothing"
    assert registry_phrases, "the registry rung's scan greps for nothing"
    engine_log = _what_the_ladder_logs(engine_holds_the_image=True)
    registry_log = _what_the_ladder_logs(engine_holds_the_image=False)
    for phrase in engine_phrases:
        assert phrase in engine_log, f"{phrase!r} is not in: {engine_log}"
    for phrase in registry_phrases:
        assert phrase in registry_log, f"{phrase!r} is not in: {registry_log}"
