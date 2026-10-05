# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The output-path exclusion must not depend on the process working directory.

The defect
----------
``apply_suppressions_to_sarif`` drops findings whose location is inside the output
directory but outside the work directory -- ASH's own reports are not findings
about the scanned tree. It decided that with ``Path(uri).resolve()``, and by that
point ``uri`` has had the source-directory prefix stripped off it, so it is
relative *to the source directory*. ``Path.resolve`` on a relative path anchors on
the process's current working directory instead.

Those two agree only when ``cwd == source_dir``, which is the common interactive
case and the reason this survived. Run from anywhere else -- a CI job that checks
out to one directory and passes ``--source-dir`` for another, ``ash merge``, any
MCP session -- and the resolution lands on a path that does not exist, is not under
the output directory, and the exclusion silently stops firing. ASH's own HTML and
SARIF reports then come back as findings about the customer's repository.

The control pair is the whole test
----------------------------------
Identical input, two different working directories, asserting the same exclusion
decision. Asserting the correct decision at one cwd would pass on the broken code
whenever that cwd happened to be ``source_dir``.

The containment case
--------------------
Anchoring correctly makes a second, worse configuration reachable deterministically
rather than by accident: if the output directory is an ancestor of the source
directory, *every* finding resolves inside it and the exclusion empties the run. A
scan that reports nothing is indistinguishable from a clean one, so that
configuration disables the exclusion loudly instead.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Optional
from unittest.mock import MagicMock

import pytest

from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.schemas.sarif_schema_model import Run, SarifReport
from automated_security_helper.utils import sarif_utils
from automated_security_helper.utils.sarif_utils import apply_suppressions_to_sarif


def _sarif(*uris: str) -> SarifReport:
    """One finding per URI, each with a location a scanner would emit."""
    return SarifReport(
        runs=[
            Run(
                tool={"driver": {"name": "bandit", "version": "1.0.0"}},
                results=[
                    {
                        "ruleId": f"RULE-{index}",
                        "message": {"text": "finding"},
                        "level": "warning",
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": uri},
                                    "region": {"startLine": 1, "endLine": 1},
                                }
                            }
                        ],
                    }
                    for index, uri in enumerate(uris)
                ],
            )
        ]
    )


def _context(source_dir: Path, output_dir: Path) -> MagicMock:
    ctx = MagicMock()
    ctx.source_dir = source_dir
    ctx.output_dir = output_dir
    ctx.ignore_suppressions = False
    ctx.config = MagicMock()
    ctx.config.global_settings.ignore_paths = []
    ctx.config.global_settings.suppressions = []
    return ctx


def _rule_ids(report: SarifReport) -> List[str]:
    return [result.ruleId for result in report.runs[0].results or []]


@pytest.fixture
def tree(tmp_path: Path):
    """A source tree with ASH's own output nested inside it, as a real scan has.

    ``output_dir`` under ``source_dir`` is the shipped default -- ``cli/scan.py``
    derives ``<source_dir>/.ash/ash_output`` -- and it is the only layout in which
    the exclusion has anything to do.
    """
    source = tmp_path / "repo"
    output = source / ".ash" / "ash_output"
    work = output / ASH_WORK_DIR_NAME
    (source / "pkg").mkdir(parents=True)
    (source / "pkg" / "app.py").write_text("x = 1\n", encoding="utf-8")
    (output / "reports").mkdir(parents=True)
    (output / "reports" / "ash.html").write_text("<html></html>", encoding="utf-8")
    work.mkdir(parents=True)
    (work / "converted.py").write_text("x = 1\n", encoding="utf-8")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    return source, output, elsewhere


def _decide(
    monkeypatch,
    cwd: Path,
    source: Path,
    output: Path,
    *uris: str,
) -> List[str]:
    """Rule ids surviving the pass, with the process cwd set to *cwd*."""
    monkeypatch.chdir(cwd)
    return _rule_ids(
        apply_suppressions_to_sarif(_sarif(*uris), _context(source, output))
    )


class TestTheDecisionIsTheSameFromEveryWorkingDirectory:
    """The certificate's control pair, as a parametrized pair of cwds."""

    def test_a_report_inside_the_output_dir_is_dropped_from_either_cwd(
        self, tree, monkeypatch
    ):
        source, output, elsewhere = tree
        uri = (output / "reports" / "ash.html").as_posix()

        from_source = _decide(monkeypatch, source, source, output, uri)
        from_elsewhere = _decide(monkeypatch, elsewhere, source, output, uri)

        assert from_source == from_elsewhere, (
            "the exclusion decision moved with the process working directory: "
            f"{from_source} from source_dir versus {from_elsewhere} from an "
            "unrelated cwd"
        )
        assert from_elsewhere == []

    def test_a_real_source_finding_survives_from_either_cwd(self, tree, monkeypatch):
        """The control. Without it, "drop everything" satisfies the test above."""
        source, output, elsewhere = tree
        uri = (source / "pkg" / "app.py").as_posix()

        from_source = _decide(monkeypatch, source, source, output, uri)
        from_elsewhere = _decide(monkeypatch, elsewhere, source, output, uri)

        assert from_source == from_elsewhere == ["RULE-0"]

    def test_a_finding_in_the_work_dir_survives_from_either_cwd(
        self, tree, monkeypatch
    ):
        """The work directory is the documented hole in the exclusion.

        Converted sources live there, and a finding in a converted file is a real
        finding about the source it was converted from. Pinned at both cwds because
        the work-directory test is the second half of the same resolution.
        """
        source, output, elsewhere = tree
        uri = (output / ASH_WORK_DIR_NAME / "converted.py").as_posix()

        from_source = _decide(monkeypatch, source, source, output, uri)
        from_elsewhere = _decide(monkeypatch, elsewhere, source, output, uri)

        assert from_source == from_elsewhere == ["RULE-0"]

    def test_a_relative_uri_is_anchored_on_the_source_dir(self, tree, monkeypatch):
        """The shape the anchor actually sees.

        ``_normalize_sarif_uri`` strips the source-directory prefix, so by the time
        the exclusion runs the URI is relative to ``source_dir``. Handing it one
        already in that form, from an unrelated cwd, is the narrowest statement of
        the defect.
        """
        source, output, elsewhere = tree

        surviving = _decide(
            monkeypatch,
            elsewhere,
            source,
            output,
            ".ash/ash_output/reports/ash.html",
        )

        assert surviving == []

    def test_an_absolute_uri_outside_the_source_tree_is_not_relocated(
        self, tree, monkeypatch
    ):
        """A URI the prefix strip did not match stays absolute, and must stay put.

        Scanners emit absolute paths for files outside the scanned tree -- a
        system-wide config, a cached dependency. Joining one onto ``source_dir``
        must not fabricate a path inside it; ``pathlib`` discards the left operand
        when the right is absolute, which is what makes the join safe here rather
        than merely convenient.
        """
        source, output, elsewhere = tree
        outside = (elsewhere / "vendor.py").as_posix()

        surviving = _decide(monkeypatch, elsewhere, source, output, outside)

        assert surviving == ["RULE-0"]


class TestAnOutputDirContainingTheSourceDirDisablesTheExclusion:
    """The configuration in which the exclusion would empty the whole run.

    ``ash merge`` builds its plugin context with ``source_dir=Path.cwd()`` and the
    operator's ``--output-dir`` verbatim, so ``ash merge --output-dir .`` makes the
    output directory an ancestor of the source directory. With the anchor fixed,
    every finding then resolves inside the output directory and the exclusion drops
    the entire result set -- at exit 0, because a run with no findings is clean.
    """

    @pytest.fixture
    def capture(self, caplog):
        """Route ASH_LOGGER at WARNING into caplog without the rich handler.

        Same shape as ``tests/unit/utils/test_get_scan_set_coverage.py``: the
        logger's own handlers are swapped for pytest's capture handlers, because
        ASH's configured handler writes to a console and leaves nothing in
        ``caplog.records``.
        """
        logger = sarif_utils.ASH_LOGGER
        saved_handlers = logger.handlers
        saved_propagate = logger.propagate
        capture_handlers = [
            handler
            for handler in saved_handlers
            if isinstance(handler, type(caplog.handler))
        ]
        if caplog.handler not in capture_handlers:
            capture_handlers.append(caplog.handler)
        logger.handlers = capture_handlers
        logger.propagate = False
        caplog.set_level(logging.WARNING, logger=logger.name)
        try:
            yield caplog
        finally:
            logger.handlers = saved_handlers
            logger.propagate = saved_propagate

    @staticmethod
    def _messages(capture, needle: str) -> Optional[str]:
        for record in capture.records:
            if needle in record.getMessage():
                return record.getMessage()
        return None

    def test_findings_in_the_source_tree_survive(self, tmp_path, monkeypatch, capture):
        source = tmp_path / "repo"
        (source / "pkg").mkdir(parents=True)
        (source / "pkg" / "app.py").write_text("x = 1\n", encoding="utf-8")
        monkeypatch.chdir(source)

        surviving = _rule_ids(
            apply_suppressions_to_sarif(
                _sarif((source / "pkg" / "app.py").as_posix()),
                # output_dir is an ancestor of source_dir.
                _context(source, tmp_path),
            )
        )

        assert surviving == ["RULE-0"]

    def test_the_refusal_is_logged_at_warning(self, tmp_path, monkeypatch, capture):
        """Silently declining to apply a guard is how a guard becomes decoration."""
        source = tmp_path / "repo"
        (source / "pkg").mkdir(parents=True)
        (source / "pkg" / "app.py").write_text("x = 1\n", encoding="utf-8")
        monkeypatch.chdir(source)

        apply_suppressions_to_sarif(
            _sarif((source / "pkg" / "app.py").as_posix()),
            _context(source, tmp_path),
        )

        message = self._messages(capture, "output directory")
        assert message is not None, [r.getMessage() for r in capture.records]
        assert "ancestor" in message

    def test_an_ordinary_layout_does_not_disable_the_exclusion(
        self, tree, monkeypatch, capture
    ):
        """The control. The guard must not switch the exclusion off everywhere."""
        source, output, elsewhere = tree

        surviving = _decide(
            monkeypatch,
            elsewhere,
            source,
            output,
            (output / "reports" / "ash.html").as_posix(),
        )

        assert surviving == []
        assert self._messages(capture, "ancestor") is None


class TestWhatTheExclusionDropsIsCounted:
    """A pass that can empty a whole run must say how much it removed."""

    @pytest.fixture
    def capture(self, caplog):
        logger = sarif_utils.ASH_LOGGER
        saved_handlers = logger.handlers
        saved_propagate = logger.propagate
        capture_handlers = [
            handler
            for handler in saved_handlers
            if isinstance(handler, type(caplog.handler))
        ]
        if caplog.handler not in capture_handlers:
            capture_handlers.append(caplog.handler)
        logger.handlers = capture_handlers
        logger.propagate = False
        caplog.set_level(logging.WARNING, logger=logger.name)
        try:
            yield caplog
        finally:
            logger.handlers = saved_handlers
            logger.propagate = saved_propagate

    @staticmethod
    def _count_reports(capture, output: Path) -> List[str]:
        """WARNING records naming the output directory and a removal count.

        Selected on the output directory's own path -- a value the caller supplied,
        not a phrase from the message -- and on the word the removal report starts
        with, which is what separates it from the containment warning ("Not
        excluding ..."). Matching on prose alone would tie this to wording that is
        free to change.
        """
        needle = output.resolve().as_posix()
        return [
            record.getMessage()
            for record in capture.records
            if record.levelno >= logging.WARNING
            and needle in record.getMessage()
            and record.getMessage().startswith("Excluded ")
        ]

    def test_a_non_zero_count_is_reported_at_warning(self, tree, monkeypatch, capture):
        source, output, elsewhere = tree
        second = output / "reports" / "ash.sarif"
        second.write_text("{}", encoding="utf-8")
        monkeypatch.chdir(elsewhere)

        apply_suppressions_to_sarif(
            _sarif(
                (output / "reports" / "ash.html").as_posix(),
                second.as_posix(),
                (source / "pkg" / "app.py").as_posix(),
            ),
            _context(source, output),
        )

        reports = self._count_reports(capture, output)
        assert reports, [r.getMessage() for r in capture.records]
        # Two dropped of three offered, so the number is a count of removals and not
        # a total. Asserted as a prefix rather than as substring membership: the
        # message embeds a tmp_path, and pytest's own directory numbering supplies
        # whatever digits it likes.
        assert reports[0].startswith("Excluded 2 ")

    def test_dropping_nothing_stays_quiet(self, tree, monkeypatch, capture):
        """The control. A count logged unconditionally is noise on every scan."""
        source, output, elsewhere = tree
        monkeypatch.chdir(elsewhere)

        apply_suppressions_to_sarif(
            _sarif((source / "pkg" / "app.py").as_posix()),
            _context(source, output),
        )

        assert self._count_reports(capture, output) == []
