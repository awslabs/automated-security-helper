# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A global ignore path ending in ``/`` names a directory and ignores what is in it.

Ignore paths are matched as globs against a file's path below the source directory,
and ``vendor/`` matched no file: a file's path never ends in ``/``. An operator who
wrote ``vendor/``, as a .gitignore would, had every file there scanned and reported.

ASH's built-in scanner exclusions (``node_modules/``, ``.venv/``, ``venv/``) were also
passed to the findings step as ignore paths, and matched nothing for the same reason.
They are no longer passed: read as directories they would drop every finding a
dependency scanner reports there, all of npm-audit's among them.

Now an ignore path ending in ``/`` (or ``\\``) is matched as ``<dir>/**``, at every
place ignore paths are matched: dropping findings, keeping files from the converters
and from detect-secrets, the exclusions each tree-walking scanner is given, and
snyk-code's refusal. Like any ignore path it is anchored at the source directory:
``vendor/`` is the top-level ``vendor`` directory, and ``**/vendor/`` is one at any
depth.

Suppressions keep their meaning. A suppression path ending in ``/`` still matches
only that literal path, so it suppresses nothing; ASH warns once, after the scan,
for each such suppression that matched no finding, and names ``<dir>/**``.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List
from unittest.mock import MagicMock

import pytest

from automated_security_helper.models.core import AshSuppression, IgnorePathWithReason
from automated_security_helper.schemas.sarif_schema_model import Run, SarifReport
from automated_security_helper.utils import suppression_matcher
from automated_security_helper.utils.link_exclusions import (
    drop_ignored,
    ignored_entries,
    ignoring_patterns,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.sarif_utils import (
    apply_suppressions_to_sarif,
    ignore_paths_for_locations,
)


def _sarif(*uris: str) -> SarifReport:
    results = [
        {
            "ruleId": "R1",
            "message": {"text": "finding"},
            "level": "warning",
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": {"startLine": 3},
                    }
                }
            ],
        }
        for uri in uris
    ]
    return SarifReport(
        runs=[Run(tool={"driver": {"name": "t", "version": "1"}}, results=results)]
    )


def _context(ignore_paths: List[str], suppressions=None) -> MagicMock:
    context = MagicMock()
    context.source_dir = Path("/src")
    context.output_dir = Path("/out")
    context.ignore_suppressions = False
    context.config.global_settings.ignore_paths = [
        IgnorePathWithReason(path=path, reason="ignored") for path in ignore_paths
    ]
    context.config.global_settings.suppressions = suppressions or []
    context.config._client_scanner_exclusions = []
    return context


def _kept(report: SarifReport) -> List[str]:
    return [
        result.locations[0].physicalLocation.root.artifactLocation.uri
        for run in report.runs
        for result in run.results or []
        if not result.suppressions
    ]


@pytest.fixture
def ash_warnings():
    records: List[logging.LogRecord] = []

    class _Collect(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _Collect(level=logging.WARNING)
    ASH_LOGGER.addHandler(handler)
    yield records
    ASH_LOGGER.removeHandler(handler)


class TestMatching:
    @pytest.mark.parametrize(
        "path, pattern, expected",
        [
            ("vendor/a.py", "vendor/", True),
            ("vendor/sub/b.py", "vendor/", True),
            ("vendor/sub/b.py", "vendor\\", True),
            ("vendorx/a.py", "vendor/", False),
            ("src/vendor/a.py", "vendor/", False),
            ("src/vendor/a.py", "**/vendor/", True),
            ("vendor/a.py", "**/vendor/", True),
            ("vendor/a.py", "vendor", False),
            ("vendor/a.py", "vendor/*", True),
        ],
    )
    def test_an_ignore_path_ending_in_a_slash_is_its_directory(
        self, path, pattern, expected
    ):
        assert suppression_matcher.ignore_path_matches(path, pattern) is expected
        entry = IgnorePathWithReason(path=pattern, reason="r")
        assert entry.matches_path(path) is expected

    def test_a_suppression_path_ending_in_a_slash_is_unchanged(self):
        suppression = AshSuppression(path="vendor/", rule_id="R1", reason="r")

        assert suppression.matches_path("vendor/a.py") is False
        assert suppression_matcher.file_path_matches("vendor/a.py", "vendor/") is False


class TestDroppedFindings:
    def test_an_ignore_path_ending_in_a_slash_drops_the_directorys_findings(self):
        report = apply_suppressions_to_sarif(
            _sarif("build/out.py", "build/deep/x.py", "src/app.py"),
            _context(["build/"]),
        )

        assert _kept(report) == ["src/app.py"]

    def test_the_built_in_scanner_exclusions_do_not_drop_findings(self):
        """KNOWN_IGNORE_PATHS (node_modules/, .venv/, venv/) are bandit's and
        checkov's exclusions. As ignore paths they matched nothing; read as
        directories they would drop every npm-audit finding, which is located at
        node_modules/<package>/package.json."""
        uris = [
            "node_modules/braces/package.json",
            "web/node_modules/pkg/package.json",
            ".venv/lib/site.py",
            "svc/venv/lib/site.py",
            "src/app.py",
        ]

        report = apply_suppressions_to_sarif(_sarif(*uris), _context([]))

        assert _kept(report) == uris

    def test_a_suppression_path_ending_in_a_slash_still_suppresses_nothing(self):
        suppression = AshSuppression(path="build/", rule_id="R1", reason="r")

        report = apply_suppressions_to_sarif(
            _sarif("build/out.py"), _context([], suppressions=[suppression])
        )

        assert _kept(report) == ["build/out.py"]


class TestUnmatchedDirectorySuppressions:
    def test_one_warning_names_the_directory_glob(self, ash_warnings):
        unmatched = AshSuppression(path="build/", rule_id="R1", reason="r")
        used = AshSuppression(path="lib/", rule_id="R2", reason="r")
        plain = AshSuppression(path="docs/*", rule_id="R3", reason="r")

        suppression_matcher.warn_unmatched_directory_suppressions(
            [unmatched, used, plain], used_ids={used.id}
        )

        messages = [record.getMessage() for record in ash_warnings]
        assert len(messages) == 1, messages
        assert "'build/'" in messages[0]
        assert "'build/**'" in messages[0]

    def test_nothing_is_said_when_every_such_suppression_matched(self, ash_warnings):
        used = AshSuppression(path="lib/", rule_id="R2", reason="r")

        suppression_matcher.warn_unmatched_directory_suppressions(
            [used], used_ids={used.id}
        )

        assert ash_warnings == []


class TestTheScannersExclusions:
    def test_the_walking_scanners_are_given_the_directory(self, tmp_path):
        source = tmp_path / "src"
        (source / "thirdparty" / "sub").mkdir(parents=True)
        (source / "thirdparty" / "a.js").write_text("a\n", encoding="utf-8")
        (source / "thirdparty" / "sub" / "b.js").write_text("b\n", encoding="utf-8")
        (source / "app.js").write_text("c\n", encoding="utf-8")
        files = ["app.js", "thirdparty/a.js", "thirdparty/sub/b.js"]
        ignore = [IgnorePathWithReason(path="thirdparty/", reason="vendored")]

        assert ignored_entries(source, source, ignore, files) == ["thirdparty/"]
        kept = drop_ignored([str(source / name) for name in files], source, ignore)
        assert kept == [str(source / "app.js")]
        assert ignoring_patterns([str(source / "thirdparty" / "a.js")], source, ignore)

    def test_snyk_codes_refusal_matches_the_directory(self):
        """snyk-code's refusal calls the findings step's own match."""
        ignore = [IgnorePathWithReason(path="thirdparty/", reason="vendored")]

        found = ignore_paths_for_locations(
            ["app.js", "thirdparty/a.js", "thirdparty/sub/b.js"], _context([]), ignore
        )

        assert sorted(found) == ["thirdparty/a.js", "thirdparty/sub/b.js"]


def test_the_archive_converter_skips_an_archive_below_it(test_plugin_context):
    from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
        ArchiveConverter,
        ArchiveConverterConfig,
    )

    converter = ArchiveConverter(
        context=test_plugin_context, config=ArchiveConverterConfig()
    )
    test_plugin_context.config.global_settings.ignore_paths = [
        IgnorePathWithReason(path="vendor/", reason="third-party code")
    ]
    source = Path(test_plugin_context.source_dir)

    assert converter._skipped(str(source / "vendor" / "deps.zip")) is True
    assert converter._skipped(str(source / "app" / "bundle.zip")) is False
