# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ignore_paths[].expiration`` is enforced the way ``suppressions[].expiration`` is.

The rule both follow is the one suppressions have always had
(``utils/suppression_matcher.py``): ``expiration`` is a YYYY-MM-DD date read on
this host's clock, the entry stops applying at the start of that day (so on the
expiration date itself it no longer applies), a date that is not YYYY-MM-DD
refuses the config when it is loaded, and an entry that expires within 30 days
is named in a warning when the scan starts.

Ignore paths are applied in more than one place: the scanners that pre-filter
their file lists get them from the orchestrator, the archive and Jupyter
converters read them from the config, and the SARIF step drops the findings in
them after the scan. Each place is tested here, because enforcing the date in
one of them and not the others is the defect this file exists to prevent.

Every test fixes the clock at ``TODAY``, so "the day before", "the day itself"
and "the day after" are exact days rather than offsets from whenever the suite
happens to run.
"""

import ast
import glob
import io
import json
import logging
import subprocess
import zipfile
from datetime import date, datetime
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import ValidationError
from rich.console import Console
from rich.logging import RichHandler

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.uv_tool_mixin import UVToolMixin
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.config_linter import (
    ConfigLinter,
    LintCategory,
    LintSeverity,
)
from automated_security_helper.config.resolve_config import (
    ConfigFileRefused,
    resolve_config,
)
from automated_security_helper.core.exceptions import WorkspaceDefinitionError
from automated_security_helper.core.orchestrator import ASHScanOrchestrator
from automated_security_helper.models import asharp_model
from automated_security_helper.models import core as models_core
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.core import AshSuppression, IgnorePathWithReason
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
    ArchiveConverter,
    ArchiveConverterConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.event_handlers.suppression_expiration_checker import (
    handle_suppression_expiration_check,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
    BanditScanner,
    BanditScannerConfig,
    BanditScannerConfigOptions,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    CheckovScanner,
    CheckovScannerConfig,
    CheckovScannerConfigOptions,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.syft_scanner import (
    SyftScanner,
    SyftScannerConfig,
    SyftScannerConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Location,
    Message,
    PhysicalLocation2,
    Region,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils import suppression_matcher
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.sarif_utils import apply_suppressions_to_sarif

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()

TODAY = date(2026, 6, 15)

# (expiration, whether the entry still applies on TODAY). The same table drives
# ignore paths and suppressions, so the two cannot drift apart unnoticed.
EXPIRY_TABLE = [
    pytest.param(None, True, id="no-expiration"),
    pytest.param("2026-07-15", True, id="a-month-ahead"),
    pytest.param("2026-06-16", True, id="expires-tomorrow"),
    pytest.param("2026-06-15", False, id="expires-today"),
    pytest.param("2026-06-14", False, id="expired-yesterday"),
    pytest.param("2000-01-01", False, id="long-expired"),
]

FINDING_PATH = "vendor/lib.py"
IGNORE_PATTERN = "vendor/**"


class _FixedDatetime(datetime):
    """``datetime`` whose ``now()`` is noon on ``TODAY``.

    Noon rather than midnight, so a comparison that slipped to a timezone-aware
    clock would still land on the same calendar day.
    """

    @classmethod
    def now(cls, tz=None):
        return cls(TODAY.year, TODAY.month, TODAY.day, 12, 0, 0, tzinfo=tz)


class _FixedDate(date):
    """``date`` whose ``today()`` is ``TODAY``."""

    @classmethod
    def today(cls):
        return cls(TODAY.year, TODAY.month, TODAY.day)


@pytest.fixture
def fixed_clock(monkeypatch):
    """Fix every clock an expiration is compared against.

    Both names are patched: ``models.core.current_date`` reads ``date.today()``,
    and the matcher once read ``datetime.now()`` itself. Patching both keeps the
    fixture correct for any code that still reads either one.
    """
    monkeypatch.setattr(models_core, "date", _FixedDate)
    monkeypatch.setattr(suppression_matcher, "datetime", _FixedDatetime)


def _sarif_with_one_finding(uri: str = FINDING_PATH) -> SarifReport:
    return SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="Test Scanner", version="1.0")),
                results=[
                    Result(
                        ruleId="RULE-1",
                        message=Message(text="finding in a vendored file"),
                        locations=[
                            Location(
                                physicalLocation=PhysicalLocation2(
                                    artifactLocation=ArtifactLocation(uri=uri),
                                    region=Region(startLine=1, endLine=1),
                                )
                            )
                        ],
                    )
                ],
            )
        ],
    )


def _context(tmp_path: Path, config: AshConfig) -> PluginContext:
    source = tmp_path / "source"
    source.mkdir(exist_ok=True)
    output = tmp_path / "output"
    output.mkdir(exist_ok=True)
    return PluginContext(source_dir=source, output_dir=output, config=config)


def _config(ignore_paths=(), suppressions=()) -> AshConfig:
    return AshConfig(
        project_name="test-project",
        global_settings={
            "ignore_paths": list(ignore_paths),
            "suppressions": list(suppressions),
        },
    )


@pytest.mark.usefixtures("fixed_clock")
class TestPostScanFiltering:
    """``apply_suppressions_to_sarif`` drops findings only for live ignore paths."""

    @pytest.mark.parametrize("expiration,applies", EXPIRY_TABLE)
    def test_ignore_path_applies_until_its_expiration_day(
        self, tmp_path, expiration, applies
    ):
        config = _config(
            ignore_paths=[
                IgnorePathWithReason(
                    path=IGNORE_PATTERN, reason="vendored", expiration=expiration
                )
            ]
        )
        result = apply_suppressions_to_sarif(
            _sarif_with_one_finding(), _context(tmp_path, config)
        )

        remaining = result.runs[0].results
        if applies:
            assert remaining == [], (
                f"an ignore path expiring {expiration} still applies on {TODAY}, "
                "so the finding in it must be dropped"
            )
        else:
            assert len(remaining) == 1, (
                f"an ignore path that expired on {expiration} must stop excluding "
                f"{FINDING_PATH} on {TODAY}, but the finding was still dropped"
            )

    @pytest.mark.parametrize("expiration,applies", EXPIRY_TABLE)
    def test_a_suppression_with_the_same_date_agrees(
        self, tmp_path, expiration, applies
    ):
        """The reference behavior the ignore-path rule is held to."""
        config = _config(
            suppressions=[
                AshSuppression(
                    rule_id="RULE-1",
                    path=FINDING_PATH,
                    reason="accepted",
                    expiration=expiration,
                )
            ]
        )
        result = apply_suppressions_to_sarif(
            _sarif_with_one_finding(), _context(tmp_path, config)
        )

        (finding,) = result.runs[0].results
        assert bool(finding.suppressions) is applies

    def test_only_the_expired_entry_of_several_is_dropped(self, tmp_path):
        config = _config(
            ignore_paths=[
                IgnorePathWithReason(
                    path=IGNORE_PATTERN, reason="vendored", expiration="2026-06-01"
                ),
                IgnorePathWithReason(path="build/**", reason="generated"),
            ]
        )
        sarif = _sarif_with_one_finding()
        sarif.runs[0].results.append(
            _sarif_with_one_finding("build/out.py").runs[0].results[0]
        )

        result = apply_suppressions_to_sarif(sarif, _context(tmp_path, config))

        uris = [
            r.locations[0].physicalLocation.root.artifactLocation.uri
            for r in result.runs[0].results
        ]
        assert uris == [FINDING_PATH]


@pytest.mark.usefixtures("fixed_clock")
class TestScannerPreFiltering:
    """The scanners that pre-filter receive only live ignore paths.

    Bandit, detect-secrets and ferret-scan exclude ``global_ignore_paths`` from
    the files they scan. They all receive the list the orchestrator hands the
    execution engine, so that is where an expired entry has to be left out.
    """

    def test_orchestrator_passes_only_live_ignore_paths_to_the_engine(self, tmp_path):
        live = IgnorePathWithReason(
            path="build/**", reason="generated", expiration="2026-06-16"
        )
        expired = IgnorePathWithReason(
            path=IGNORE_PATTERN, reason="vendored", expiration="2026-06-15"
        )
        config = _config(ignore_paths=[live, expired])
        source = tmp_path / "src"
        source.mkdir()
        orchestrator = ASHScanOrchestrator(
            source_dir=source,
            output_dir=tmp_path / "out",
            config_path=None,
            config_overrides=None,
            no_cleanup=False,
            metadata=None,
            ash_plugin_modules=[],
        )
        with (
            patch(
                "automated_security_helper.core.orchestrator.resolve_config",
                return_value=config,
            ),
            patch(
                "automated_security_helper.core.orchestrator.ScanExecutionEngine"
            ) as engine,
        ):
            orchestrator.initialize()

        passed = engine.call_args.kwargs["global_ignore_paths"]
        assert [p.path for p in passed] == ["build/**"], (
            "the scanners that pre-filter were handed an ignore path that expired "
            "today, so they would still skip its files"
        )
        # The config itself is left as written: the aggregated results report
        # the entry, and only its application stops.
        assert [p.path for p in config.global_settings.ignore_paths] == [
            "build/**",
            IGNORE_PATTERN,
        ]


@pytest.mark.usefixtures("fixed_clock")
class TestArchiveConverter:
    """An archive under an expired ignore path is extracted and scanned again."""

    def _convert(self, tmp_path, monkeypatch, expiration):
        config = _config(
            ignore_paths=[
                IgnorePathWithReason(
                    path="vendor/*", reason="vendored", expiration=expiration
                )
            ]
        )
        context = _context(tmp_path, config)
        archive = context.source_dir / "vendor" / "bundle.zip"
        archive.parent.mkdir(parents=True)
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("inner.py", "print('x')\n")
        monkeypatch.setattr(
            "automated_security_helper.plugin_modules.ash_builtin.converters."
            "archive_converter.scan_set",
            lambda *args, **kwargs: [str(archive)],
        )
        converter = ArchiveConverter(context=context, config=ArchiveConverterConfig())
        return converter.convert()

    def test_live_ignore_path_skips_the_archive(self, tmp_path, monkeypatch):
        assert self._convert(tmp_path, monkeypatch, "2026-06-16") == []

    def test_expired_ignore_path_no_longer_skips_the_archive(
        self, tmp_path, monkeypatch
    ):
        results = self._convert(tmp_path, monkeypatch, "2026-06-15")
        assert len(results) == 1, (
            "the ignore path expired today, so vendor/bundle.zip must be converted"
        )
        assert (results[0] / "inner.py").exists()


class TestMalformedExpiration:
    """A date that is not YYYY-MM-DD refuses the config, as it does for a suppression."""

    @pytest.mark.parametrize("written", ["2026/06/30", "30-06-2026", "soon", ""])
    def test_model_refuses_a_malformed_date(self, written):
        with pytest.raises(ValidationError) as excinfo:
            IgnorePathWithReason(path="vendor/**", reason="r", expiration=written)
        assert "YYYY-MM-DD" in str(excinfo.value)

    def test_suppression_refuses_the_same_dates(self):
        with pytest.raises(ValidationError):
            AshSuppression(path="a.py", reason="r", expiration="2026/06/30")

    def test_config_file_with_a_malformed_date_is_refused(self, tmp_path):
        """The scanned repository's own config is refused whole, never applied in part.

        A discovered in-tree config with a malformed date is refused as a
        named one is: resolve_config re-raises the file's refusal
        (config/resolve_config.py, the ConfigFileRefused arm: "refused, never
        replaced by the default config, for a discovered file as for a named
        one"), so the scan exits 3 instead of running with the file's ignore
        paths and suppressions switched off, and the refusal names the date
        rule. This test pins that refusal: it asserts ``resolve_config`` raises,
        so a change that contains such a file instead (warns about it and
        resolves without it) turns it red on purpose. Which of the two a scan
        should do is a question of contract, not of this test; the pin is here
        so that the change is made knowingly. A config the operator NAMED with the same date raises the same way;
        the workspace policy's own refusal is TestWorkspacePolicy's subject.
        """
        source = tmp_path / "src"
        source.mkdir()
        (source / ".ash.yaml").write_text(
            "project_name: demo\n"
            "global_settings:\n"
            "  ignore_paths:\n"
            "    - path: 'vendor/**'\n"
            "      reason: vendored\n"
            "      expiration: '2026/06/30'\n",
            encoding="utf-8",
        )
        with pytest.raises(ConfigFileRefused) as excinfo:
            resolve_config(source_dir=source)
        assert "YYYY-MM-DD" in str(excinfo.value)

    def test_unvalidated_malformed_entry_is_not_applied(self, tmp_path):
        """An entry built without validation fails toward scanning, with a warning.

        ``model_construct`` skips validators, as any code that builds the model
        that way would. The matcher treats an unreadable date the way it treats
        one on a suppression: the entry is not applied, and a warning names it
        by its location, not by its path or its date.
        """
        entry = IgnorePathWithReason.model_construct(
            path=IGNORE_PATTERN, reason="vendored", expiration="2026/06/30"
        )
        config = _config()
        config.global_settings.ignore_paths = [entry]
        with patch(
            "automated_security_helper.utils.suppression_matcher.ASH_LOGGER"
        ) as logger:
            result = apply_suppressions_to_sarif(
                _sarif_with_one_finding(), _context(tmp_path, config)
            )
        assert len(result.runs[0].results) == 1
        warned = [str(c.args[0]) for c in logger.warning.call_args_list]
        assert any("global_settings.ignore_paths[0]" in w for w in warned), warned
        assert not any(IGNORE_PATTERN in w or "2026/06/30" in w for w in warned), warned


@pytest.mark.usefixtures("fixed_clock")
class TestExpiryWarning:
    """The scan-start warning names ignore paths that expire within 30 days."""

    @staticmethod
    def _warnings(tmp_path, config) -> list[str]:
        context = _context(tmp_path, config)
        with patch(
            "automated_security_helper.plugin_modules.ash_builtin.event_handlers."
            "suppression_expiration_checker.ASH_LOGGER"
        ) as logger:
            assert handle_suppression_expiration_check(plugin_context=context)
        return [str(c.args[0]) for c in logger.warning.call_args_list]

    def test_ignore_path_expiring_soon_is_named_without_any_suppressions(
        self, tmp_path
    ):
        warnings = self._warnings(
            tmp_path,
            _config(
                ignore_paths=[
                    IgnorePathWithReason(
                        path=IGNORE_PATTERN,
                        reason="vendored until the upgrade",
                        expiration="2026-07-01",
                    )
                ]
            ),
        )
        assert any("ignore paths will expire within 30 days" in w for w in warnings)
        assert any(
            IGNORE_PATTERN in w and "2026-07-01" in w and "vendored until" in w
            for w in warnings
        ), warnings

    @pytest.mark.parametrize("expiration", ["2026-08-30", "2026-06-14", None], ids=str)
    def test_ignore_path_outside_the_window_is_not_named(self, tmp_path, expiration):
        warnings = self._warnings(
            tmp_path,
            _config(
                ignore_paths=[
                    IgnorePathWithReason(
                        path=IGNORE_PATTERN, reason="vendored", expiration=expiration
                    )
                ]
            ),
        )
        # Yesterday's entry is named by the expired-entries warning instead
        # (TestExpiredEntriesWarning); none of the three "will expire".
        assert not any("will expire" in w for w in warnings), warnings
        if expiration != "2026-06-14":
            assert warnings == []

    def test_suppressions_are_warned_about(self, tmp_path):
        warnings = self._warnings(
            tmp_path,
            _config(
                suppressions=[
                    AshSuppression(
                        rule_id="B101",
                        path="a.py",
                        reason="accepted",
                        expiration="2026-06-20",
                    )
                ]
            ),
        )
        assert any("suppressions will expire within 30 days" in w for w in warnings)

    def test_nothing_expiring_is_warned_about_under_ignore_suppressions(self, tmp_path):
        """--ignore-suppressions lifts the suppressions and the global ignore paths.

        ``models.core.ignore_paths_that_skip_scanning`` hands the scanners and
        converters no global ignore path under the flag and the SARIF step
        applies none (docs/content/concepts/suppressions.md), so a global ignore
        path's expiry changes nothing about the run either, and the checker names
        neither kind. A scanner's own option list (bandit ``excluded_paths``,
        checkov ``skip_path``, syft ``exclude``) is not lifted and is still
        checked (TestExpiryWarningsCoverScannerOptionLists). This test used to
        expect the ignore path to be warned about on the reading that the flag
        turned off suppressions only.
        """
        config = _config(
            ignore_paths=[
                IgnorePathWithReason(
                    path=IGNORE_PATTERN, reason="vendored", expiration="2026-07-01"
                )
            ],
            suppressions=[
                AshSuppression(
                    rule_id="B101", path="a.py", reason="r", expiration="2026-06-20"
                )
            ],
        )
        context = _context(tmp_path, config)
        context.ignore_suppressions = True
        with patch(
            "automated_security_helper.plugin_modules.ash_builtin.event_handlers."
            "suppression_expiration_checker.ASH_LOGGER"
        ) as logger:
            assert handle_suppression_expiration_check(plugin_context=context)
        warnings = [str(c.args[0]) for c in logger.warning.call_args_list]
        assert warnings == [], warnings

    def test_an_entry_expiring_today_is_not_called_one_that_will_expire(self, tmp_path):
        """On its expiration date an entry has already stopped applying."""
        warnings = self._warnings(
            tmp_path,
            _config(
                ignore_paths=[
                    IgnorePathWithReason(
                        path=IGNORE_PATTERN, reason="vendored", expiration="2026-06-15"
                    )
                ],
                suppressions=[
                    AshSuppression(
                        rule_id="B101", path="a.py", reason="r", expiration="2026-06-15"
                    )
                ],
            ),
        )
        assert not any("will expire" in w for w in warnings), warnings


@pytest.mark.usefixtures("fixed_clock")
class TestExpiredEntriesWarning:
    """One scan-start warning lists the entries that have already expired.

    An expired entry changes what a scan reports -- its files are scanned again,
    its findings count again -- so a scan whose exit code flipped overnight has to
    say why, and say it once rather than once per finding or per scanner.
    """

    @staticmethod
    def _warnings(tmp_path, config, ignore_suppressions=False) -> list[str]:
        context = _context(tmp_path, config)
        context.ignore_suppressions = ignore_suppressions
        with patch(
            "automated_security_helper.plugin_modules.ash_builtin.event_handlers."
            "suppression_expiration_checker.ASH_LOGGER"
        ) as logger:
            assert handle_suppression_expiration_check(plugin_context=context)
        return [str(c.args[0]) for c in logger.warning.call_args_list]

    def _expired_config(self):
        return _config(
            ignore_paths=[
                IgnorePathWithReason(
                    path=IGNORE_PATTERN, reason="vendored", expiration="2026-06-01"
                ),
                IgnorePathWithReason(path="build/**", reason="generated"),
            ],
            suppressions=[
                AshSuppression(
                    rule_id="B101",
                    path="tests/a.py",
                    reason="asserts in tests",
                    expiration="2026-06-15",
                ),
                AshSuppression(
                    rule_id="B602", path="b.py", reason="r", expiration="2027-01-01"
                ),
            ],
        )

    def test_one_message_names_every_expired_entry(self, tmp_path):
        warnings = self._warnings(tmp_path, self._expired_config())
        expired = [w for w in warnings if "have expired" in w]
        assert len(expired) == 1, warnings
        (message,) = expired
        assert IGNORE_PATTERN in message and "2026-06-01" in message
        assert "B101" in message and "tests/a.py" in message and "2026-06-15" in message
        assert "build/**" not in message and "B602" not in message

    def test_nothing_is_reported_expired_under_ignore_suppressions(self, tmp_path):
        """Under the flag no suppression and no global ignore path applies, the
        expired ones included, so an expired one changes nothing about the scan and
        no message names one (a scanner's own option list is not lifted, and its
        expired entries are named: TestExpiryWarningsCoverScannerOptionLists).
        This test used to expect the expired ignore path to be named, on the
        reading that the flag turned off suppressions only."""
        warnings = self._warnings(
            tmp_path, self._expired_config(), ignore_suppressions=True
        )
        assert [w for w in warnings if "have expired" in w] == [], warnings
        assert warnings == [], warnings

    def test_nothing_expired_means_no_message(self, tmp_path):
        config = _config(
            ignore_paths=[IgnorePathWithReason(path="build/**", reason="generated")],
            suppressions=[
                AshSuppression(
                    rule_id="B602", path="b.py", reason="r", expiration="2027-01-01"
                )
            ],
        )
        assert not any("have expired" in w for w in self._warnings(tmp_path, config))

    def test_the_warnings_come_in_the_order_the_docs_show(self, tmp_path):
        """Expired entries first, then expiring ignore paths, then expiring
        suppressions: the order of the example in
        docs/content/docs/plugins/builtin/event-handlers.md."""
        config = _config(
            ignore_paths=[
                IgnorePathWithReason(
                    path="build/**", reason="generated", expiration="2026-06-01"
                ),
                IgnorePathWithReason(
                    path=IGNORE_PATTERN, reason="vendored", expiration="2026-07-01"
                ),
            ],
            suppressions=[
                AshSuppression(
                    rule_id="B101", path="a.py", reason="r", expiration="2026-07-01"
                )
            ],
        )
        headers = [
            w.splitlines()[0]
            for w in self._warnings(tmp_path, config)
            if w.startswith("The following")
        ]
        assert headers == [
            (
                "The following ignore paths and suppressions have expired and no "
                "longer apply:"
            ),
            "The following ignore paths will expire within 30 days:",
            "The following suppressions will expire within 30 days:",
        ]


@pytest.mark.usefixtures("fixed_clock")
class TestExpiryWarningsPrintConfigTextAsWritten:
    """A path or reason in an expiry warning is config text, not Rich markup.

    ASH's console handler renders markup (utils/log.py), and a bracketed span
    starting with "/" reads as a closing tag: "see [/docs/policy]" raised
    MarkupError out of the logging call, the engine re-raised it, and the scan
    failed from the day the entry expired. The handler here is built the way
    ``setup_logging`` builds it, with ``markup=True``.
    """

    TEXT = "see [/docs/policy]"

    @pytest.fixture
    def console(self, monkeypatch):
        # A buffer at width 400, off a terminal: a caller's FORCE_COLOR or
        # TTY_COMPATIBLE made Rich treat it as one, and under TERM=dumb lay it out
        # at 80 columns, which broke the reason across lines.
        for name in ("FORCE_COLOR", "TTY_COMPATIBLE", "TTY_INTERACTIVE"):
            monkeypatch.delenv(name, raising=False)
        buffer = io.StringIO()
        handler = RichHandler(
            console=Console(file=buffer, width=400, color_system=None),
            markup=True,
            show_time=False,
            show_path=False,
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
        saved_handlers, saved_level = list(ASH_LOGGER.handlers), ASH_LOGGER.level
        ASH_LOGGER.handlers = [handler]
        ASH_LOGGER.setLevel(logging.DEBUG)
        try:
            yield buffer
        finally:
            ASH_LOGGER.handlers = saved_handlers
            ASH_LOGGER.setLevel(saved_level)

    @pytest.mark.parametrize(
        "kind,expiration",
        [
            ("ignore path", "2026-06-01"),
            ("ignore path", "2026-07-01"),
            ("suppression", "2026-06-01"),
            ("suppression", "2026-07-01"),
        ],
        ids=[
            "expired-ignore-path",
            "expiring-ignore-path",
            "expired-suppression",
            "expiring-suppression",
        ],
    )
    def test_brackets_in_the_reason_are_printed(
        self, tmp_path, console, kind, expiration
    ):
        if kind == "ignore path":
            config = _config(
                ignore_paths=[
                    IgnorePathWithReason(
                        path="vendor/**", reason=self.TEXT, expiration=expiration
                    )
                ]
            )
        else:
            config = _config(
                suppressions=[
                    AshSuppression(
                        rule_id="B101",
                        path="a.py",
                        reason=self.TEXT,
                        expiration=expiration,
                    )
                ]
            )
        assert handle_suppression_expiration_check(
            plugin_context=_context(tmp_path, config)
        )
        assert self.TEXT in console.getvalue()

    def test_an_unparseable_stored_date_is_not_printed(self, tmp_path, console):
        """An entry kept from a results file, whose date was never validated.

        The path and the reason print as written; the date does not print at
        all, since a stored configuration keeps it as written and it can be a
        value read from the environment.
        """
        entry = IgnorePathWithReason.model_construct(
            path="vendor/[/x]", reason=self.TEXT, expiration="TBD-UNPARSED"
        )
        config = _config(ignore_paths=[entry])
        assert handle_suppression_expiration_check(
            plugin_context=_context(tmp_path, config)
        )
        output = console.getvalue()
        assert "vendor/[/x]" in output and self.TEXT in output
        assert "not YYYY-MM-DD" in output
        assert "TBD-UNPARSED" not in output


@pytest.mark.usefixtures("fixed_clock")
class TestExpiryWarningsCoverScannerOptionLists:
    """The scan-start warnings name entries of the three scanner option lists.

    bandit ``excluded_paths``, checkov ``skip_path`` and syft ``exclude`` take
    the same entries as ``ignore_paths``, expire by the same rule, and the
    suppressions guide promises the same warnings for them. The handler read
    only ``global_settings``.
    """

    @staticmethod
    def _warnings(tmp_path, config) -> list[str]:
        with patch(
            "automated_security_helper.plugin_modules.ash_builtin.event_handlers."
            "suppression_expiration_checker.ASH_LOGGER"
        ) as logger:
            assert handle_suppression_expiration_check(
                plugin_context=_context(tmp_path, config)
            )
        return [str(c.args[0]) for c in logger.warning.call_args_list]

    @pytest.mark.parametrize(
        "scanner,field,subject",
        [
            ("bandit", "excluded_paths", "Bandit excluded path"),
            ("checkov", "skip_path", "Checkov skip path"),
            ("syft", "exclude", "Syft exclude entry"),
        ],
    )
    def test_expired_and_expiring_entries_are_named(
        self, tmp_path, scanner, field, subject
    ):
        config = AshConfig(
            project_name="test-project",
            scanners={
                scanner: {
                    "options": {
                        field: [
                            {"path": "old", "reason": "r", "expiration": "2026-06-01"},
                            {"path": "soon", "reason": "r", "expiration": "2026-07-01"},
                            {
                                "path": "later",
                                "reason": "r",
                                "expiration": "2027-01-01",
                            },
                        ]
                    }
                }
            },
        )
        warnings = self._warnings(tmp_path, config)
        (expired,) = [w for w in warnings if "have expired" in w]
        assert f"{subject} 'old' expired on 2026-06-01" in expired, expired
        assert "'soon'" not in expired
        expiring = "\n".join(w for w in warnings if "have expired" not in w)
        assert f"{subject} 'soon' expires on 2026-07-01" in expiring, warnings
        assert "'later'" not in expiring and "'old'" not in expiring

    @pytest.mark.parametrize(
        "scanner,field,subject",
        [
            ("bandit", "excluded_paths", "Bandit excluded path"),
            ("checkov", "skip_path", "Checkov skip path"),
            ("syft", "exclude", "Syft exclude entry"),
        ],
    )
    def test_an_expired_entry_is_still_named_under_ignore_suppressions(
        self, tmp_path, scanner, field, subject
    ):
        """Red at the base: the handler returned before it looked at any list.
        The flag lifts suppressions and global ignore paths; a scanner's option
        list is handed to the tool as its own argument either way, so an
        expired entry there still changes what the tool scans. The global
        ignore path that expired too is not named, as before."""
        config = AshConfig(
            project_name="test-project",
            global_settings={
                "ignore_paths": [
                    {"path": "vendor/**", "reason": "r", "expiration": "2026-06-01"}
                ]
            },
            scanners={
                scanner: {
                    "options": {
                        field: [
                            {"path": "old", "reason": "r", "expiration": "2026-06-01"}
                        ]
                    }
                }
            },
        )
        context = _context(tmp_path, config)
        context.ignore_suppressions = True

        warnings = self._warnings_for(context)

        (expired,) = [w for w in warnings if "have expired" in w]
        assert f"{subject} 'old' expired on 2026-06-01" in expired, expired
        assert "vendor" not in expired, expired

    @pytest.mark.parametrize(
        "scanner,field,subject",
        [
            ("bandit", "excluded_paths", "Bandit excluded path"),
            ("checkov", "skip_path", "Checkov skip path"),
            ("syft", "exclude", "Syft exclude entry"),
        ],
    )
    def test_an_expiring_entry_is_still_named_under_ignore_suppressions(
        self, tmp_path, scanner, field, subject
    ):
        """An entry that will expire within 30 days is named for the same reason
        an expired one is (the test above): the tool is handed the list under
        the flag. Deleting the handler's expiring-entries call for the scanner
        lists leaves every other test green; this one goes red. The global
        ignore path that is about to expire too is not named."""
        config = AshConfig(
            project_name="test-project",
            global_settings={
                "ignore_paths": [
                    {"path": "vendor/**", "reason": "r", "expiration": "2026-07-01"}
                ]
            },
            scanners={
                scanner: {
                    "options": {
                        field: [
                            {
                                "path": "soon",
                                "reason": "r",
                                "expiration": "2026-07-01",
                            }
                        ]
                    }
                }
            },
        )
        context = _context(tmp_path, config)
        context.ignore_suppressions = True

        warnings = self._warnings_for(context)

        assert "The following ignore paths will expire within 30 days:" in warnings
        named = "\n".join(warnings)
        assert f"{subject} 'soon' expires on 2026-07-01" in named, warnings
        assert "vendor" not in named, warnings

    @staticmethod
    def _warnings_for(context) -> list[str]:
        with patch(
            "automated_security_helper.plugin_modules.ash_builtin.event_handlers."
            "suppression_expiration_checker.ASH_LOGGER"
        ) as logger:
            assert handle_suppression_expiration_check(plugin_context=context)
        return [str(c.args[0]) for c in logger.warning.call_args_list]


@pytest.mark.usefixtures("fixed_clock")
class TestScannerOptionLists:
    """Scanner options typed as ignore-path entries follow the same rule.

    ``scanners.bandit.options.excluded_paths``, ``scanners.checkov.options.skip_path``
    and ``scanners.syft.options.exclude`` share the ``IgnorePathWithReason`` model
    and its ``expiration`` field, and the published schema describes that field
    the same way for all of them.
    """

    @pytest.fixture(autouse=True)
    def _no_tool_runs(self, monkeypatch):
        """Building a scanner here must not start its tool.

        Construction asks the tool for its version: bandit ran ``uv --version``
        and ``uv tool run ... bandit --version``, checkov ran ``uv tool run ...
        checkov --version`` and wrote checkov's update cache. These tests are
        about the argument list, so the version is not needed. Any process
        still started through ``subprocess.Popen`` is refused and fails the
        test at teardown (``os.system``, ``posix_spawn`` and the like are not
        intercepted). The uv runner singleton caches a failed probe as "uv is
        not available", so it is reset at teardown, and a refusal here cannot
        fail a later test in the same worker.
        """
        from automated_security_helper.utils.uv_tool_runner import (
            reset_uv_tool_runner,
        )

        monkeypatch.setattr(
            UVToolMixin, "_get_uv_tool_version", lambda self, *args, **kwargs: None
        )
        started = []

        def refuse(popen, args, *rest, **kwargs):
            started.append(args)
            raise OSError(f"test refused to start {args!r}")

        monkeypatch.setattr(subprocess.Popen, "__init__", refuse)
        yield
        reset_uv_tool_runner()
        assert started == [], f"building a scanner started {started}"

    @staticmethod
    def _entry(expiration):
        return IgnorePathWithReason(
            path="vendor", reason="vendored", expiration=expiration
        )

    @pytest.mark.parametrize(
        "expiration,applies",
        [("2026-06-16", True), ("2026-06-15", False), ("2000-01-01", False)],
        ids=["expires-tomorrow", "expires-today", "long-expired"],
    )
    def test_bandit_excluded_paths(self, tmp_path, expiration, applies):
        context = _context(tmp_path, _config())
        scanner = BanditScanner(
            context=context,
            config=BanditScannerConfig(
                options=BanditScannerConfigOptions(
                    excluded_paths=[self._entry(expiration)]
                )
            ),
        )
        (token,) = [
            a.key for a in scanner.args.extra_args if a.key.startswith("--exclude=")
        ]
        excluded = token[len("--exclude=") :].split(",")
        anchor = glob.escape(Path(context.source_dir).as_posix())
        assert (f"{anchor}/*/vendor/*" in excluded) is applies, token

    @pytest.mark.parametrize(
        "expiration,applies",
        [("2026-06-16", True), ("2026-06-15", False), ("2000-01-01", False)],
        ids=["expires-tomorrow", "expires-today", "long-expired"],
    )
    def test_checkov_skip_path(self, tmp_path, expiration, applies):
        scanner = CheckovScanner(
            context=_context(tmp_path, _config()),
            config=CheckovScannerConfig(
                options=CheckovScannerConfigOptions(skip_path=[self._entry(expiration)])
            ),
        )
        keys = [a.key for a in scanner.args.extra_args]
        assert ("--skip-path=vendor" in keys) is applies, keys

    @pytest.mark.parametrize(
        "expiration,applies",
        [("2026-06-16", True), ("2026-06-15", False), ("2000-01-01", False)],
        ids=["expires-tomorrow", "expires-today", "long-expired"],
    )
    def test_syft_exclude(self, tmp_path, expiration, applies):
        scanner = SyftScanner(
            context=_context(tmp_path, _config()),
            config=SyftScannerConfig(
                options=SyftScannerConfigOptions(exclude=[self._entry(expiration)])
            ),
        )
        excluded = [a.value for a in scanner.args.extra_args if a.key == "--exclude"]
        assert ("vendor" in excluded) is applies, excluded

    @pytest.mark.parametrize(
        "options_cls,field",
        [
            (BanditScannerConfigOptions, "excluded_paths"),
            (CheckovScannerConfigOptions, "skip_path"),
            (SyftScannerConfigOptions, "exclude"),
        ],
    )
    def test_malformed_date_is_refused(self, options_cls, field):
        with pytest.raises(ValidationError) as excinfo:
            options_cls(
                **{field: [{"path": "vendor", "reason": "r", "expiration": "TBD"}]}
            )
        assert "YYYY-MM-DD" in str(excinfo.value)


class TestStoredResults:
    """A results file written before these checks still loads.

    ``tests/test_data/outputs/written_before_expiration_checks`` was written by
    the code before this change, from a config whose ignore path said
    ``expiration: TBD`` and whose bandit ``excluded_paths`` entry said
    ``next quarter``. That config loaded then, so its results file exists, and
    ``ash report``, ``--existing-results``, ``ash merge``, workspace reporting and
    the MCP readers all read such files back through ``AshAggregatedResults``.
    """

    FIXTURE = (
        Path(__file__).resolve().parents[2]
        / "test_data"
        / "outputs"
        / "written_before_expiration_checks"
        / "ash_aggregated_results.json"
    )

    def _load(self):
        with patch(
            "automated_security_helper.models.asharp_model.ASH_LOGGER"
        ) as logger:
            model = AshAggregatedResults.model_validate_json(
                self.FIXTURE.read_text(encoding="utf-8")
            )
        return model, logger

    def test_the_stored_config_is_kept_as_written(self):
        model, _ = self._load()
        config = model.ash_config
        assert config.project_name == "results-written-before-expiration-checks", (
            "the stored config was replaced instead of kept"
        )
        assert [p.expiration for p in config.global_settings.ignore_paths] == ["TBD"]
        bandit = config.get_plugin_config("scanner", "bandit")
        options = bandit.options if hasattr(bandit, "options") else bandit["options"]
        excluded = (
            options.excluded_paths
            if hasattr(options, "excluded_paths")
            else options["excluded_paths"]
        )
        expirations = [
            e.expiration if hasattr(e, "expiration") else e["expiration"]
            for e in excluded
        ]
        assert expirations == ["next quarter"]

    def test_loading_it_warns_once_per_refused_date(self):
        """One warning per kept date, naming where it is and why, not what it says.

        The stored value is the results file's data, and the warning reaches the
        CI log, so it names the field and the reason only.
        """
        _, logger = self._load()
        warned = [str(c.args[0]) for c in logger.warning.call_args_list]
        expiration_warnings = [w for w in warned if "YYYY-MM-DD" in w]
        assert len(expiration_warnings) == 2, warned
        assert any(
            "'global_settings.ignore_paths[0].expiration'" in w
            for w in expiration_warnings
        ), warned
        assert any(
            ".excluded_paths[0].expiration'" in w and "bandit" in w
            for w in expiration_warnings
        ), warned
        for warning in warned:
            assert "TBD" not in warning, warning
            assert "next quarter" not in warning, warning

    def test_the_warning_never_carries_the_stored_value(self):
        """A canary in a kept expiration appears in no warning, and no value that
        is a control sequence or a workflow command reaches the log."""
        canary = "wJalrXUtnFEMIK7MDENG-expiration-canary"
        for stored in (canary, canary + "\x1b[31m\n::error title=x::" + canary):
            data = json.loads(self.FIXTURE.read_text(encoding="utf-8"))
            data["ash_config"]["global_settings"]["ignore_paths"][0]["expiration"] = (
                stored
            )
            with patch(
                "automated_security_helper.models.asharp_model.ASH_LOGGER"
            ) as logger:
                model = AshAggregatedResults.model_validate(data)
            assert model.ash_config.global_settings.ignore_paths[0].expiration == (
                stored
            ), "kept as written"
            logged = " ".join(
                str(arg)
                for call in logger.method_calls
                for arg in (*call.args, *call.kwargs.values())
            )
            assert canary not in logged, logged
            assert "\x1b" not in logged and "\n::" not in logged, repr(logged)
            assert "'global_settings.ignore_paths[0].expiration'" in logged, logged

    def test_a_date_the_strict_pass_cannot_locate_still_warns(self, monkeypatch):
        """The location comes from a second validation without the tolerance.
        Should it find none, each kept date still warns, without its value."""
        monkeypatch.setattr(asharp_model, "_unreadable_expirations", lambda stored: [])
        _, logger = self._load()
        warned = [str(c.args[0]) for c in logger.warning.call_args_list]
        assert len([w for w in warned if "YYYY-MM-DD" in w]) == 2, warned
        for warning in warned:
            assert "TBD" not in warning, warning
            assert "next quarter" not in warning, warning

    @pytest.mark.parametrize(
        "wording",
        [
            "Invalid expiration date format. Use YYYY-MM-DD: {value}",
            "not a date: {value!r}",
        ],
        ids=["older-wording", "any-wording"],
    )
    def test_the_location_does_not_depend_on_the_refusal_wording(
        self, monkeypatch, wording
    ):
        """The strict pass finds a kept date by where and how it failed, not by
        the words of the refusal, which another change can reword."""

        original = models_core.expiration_date_problem

        def reworded(value):
            problem = original(value)
            return None if problem is None else wording.format(value=value)

        monkeypatch.setattr(models_core, "expiration_date_problem", reworded)

        _, logger = self._load()
        warned = [str(c.args[0]) for c in logger.warning.call_args_list]

        assert any(
            "'global_settings.ignore_paths[0].expiration'" in w for w in warned
        ), warned
        assert any(
            ".excluded_paths[0].expiration'" in w and "bandit" in w for w in warned
        ), warned

    @pytest.mark.parametrize(
        "where", ["beside-in-bandit-options", "in-the-entry-itself"]
    )
    def test_an_unknown_key_near_a_kept_date_does_not_hide_its_warning(self, where):
        """The strict pass that locates kept dates stops at a section that also
        holds an unknown key, and finds the dates elsewhere. Each kept date
        still warns, without its value."""
        data = json.loads(self.FIXTURE.read_text(encoding="utf-8"))
        if where == "beside-in-bandit-options":
            data["ash_config"]["scanners"]["bandit"]["options"]["severity_level"] = (
                "HIGH"
            )
        else:
            data["ash_config"]["global_settings"]["ignore_paths"][0]["origin"] = "p"
        with patch(
            "automated_security_helper.models.asharp_model.ASH_LOGGER"
        ) as logger:
            AshAggregatedResults.model_validate(data)
        warned = [str(c.args[0]) for c in logger.warning.call_args_list]
        assert len([w for w in warned if "YYYY-MM-DD" in w]) == 2, warned
        for warning in warned:
            assert "TBD" not in warning, warning
            assert "next quarter" not in warning, warning

    def test_the_kept_entry_is_still_not_applied(self, tmp_path):
        """Kept for the record, not for use: an unreadable date does not apply."""
        model, _ = self._load()
        assert (
            suppression_matcher.active_ignore_paths(
                model.ash_config.global_settings.ignore_paths
            )
            == []
        )

    @pytest.mark.parametrize(
        "kind", [IgnorePathWithReason, AshSuppression], ids=lambda k: k.__name__
    )
    def test_the_models_agree_that_an_unreadable_date_does_not_apply(self, kind):
        """``AshSuppression.matches``, ``active_ignore_paths`` and
        ``should_suppress_finding`` all read an unparseable date as one that does
        not apply, so a kept 'TBD' entry suppresses nothing."""
        fields = {"path": "app.py", "reason": "r", "expiration": "TBD"}
        if kind is AshSuppression:
            fields["rule_id"] = "B101"
        entry = kind.model_construct(**fields)
        assert entry.is_expired is True
        if kind is AshSuppression:
            finding = FlatVulnerability(
                id="f1",
                title="t",
                description="d",
                severity="HIGH",
                scanner="bandit",
                scanner_type="SAST",
                rule_id="B101",
                file_path="app.py",
                line_start=1,
                line_end=1,
            )
            assert entry.matches(finding) is False
            assert (
                suppression_matcher.should_suppress_finding(finding, [entry])[0]
                is False
            )
        else:
            assert suppression_matcher.active_ignore_paths([entry]) == []

    def test_a_dict_round_trip_loads_too(self):
        data = json.loads(self.FIXTURE.read_text(encoding="utf-8"))
        with patch("automated_security_helper.models.asharp_model.ASH_LOGGER"):
            model = AshAggregatedResults(**data)
        assert model.ash_config.project_name == (
            "results-written-before-expiration-checks"
        )

    def test_a_new_config_with_the_same_date_is_refused(self):
        """The tolerance is for stored results only; a config file is refused."""
        data = json.loads(self.FIXTURE.read_text(encoding="utf-8"))["ash_config"]
        with pytest.raises(ValidationError):
            AshConfig.model_validate(data)


@pytest.mark.usefixtures("fixed_clock")
class TestLint:
    """``ash config lint`` reads expiration by the rule the scan uses."""

    @staticmethod
    def _issues(tmp_path, body):
        config = tmp_path / ".ash.yaml"
        config.write_text(body, encoding="utf-8")
        return ConfigLinter.lint(config, source_dir=tmp_path).issues

    @staticmethod
    def _at(issues, prefix):
        return [i for i in issues if i.path.startswith(prefix)]

    def test_suppression_expiring_today_is_reported_as_expired(self, tmp_path):
        issues = self._issues(
            tmp_path,
            "global_settings:\n"
            "  suppressions:\n"
            "    - rule_id: B101\n"
            "      path: a.py\n"
            "      reason: r\n"
            "      expiration: '2026-06-15'\n",
        )
        expired = [
            i
            for i in self._at(issues, "global_settings.suppressions[0]")
            if i.category == LintCategory.SUPPRESSION_EXPIRED
        ]
        assert len(expired) == 1, (
            "on its expiration date the suppression no longer applies, so lint "
            f"must say so: {issues}"
        )

    def test_suppression_expiring_tomorrow_is_not_reported(self, tmp_path):
        issues = self._issues(
            tmp_path,
            "global_settings:\n"
            "  suppressions:\n"
            "    - rule_id: B101\n"
            "      path: a.py\n"
            "      reason: r\n"
            "      expiration: '2026-06-16'\n",
        )
        assert not [i for i in issues if i.category == LintCategory.SUPPRESSION_EXPIRED]

    @pytest.mark.parametrize("expiration", ["2026-06-15", "2000-01-01"])
    def test_expired_ignore_path_is_reported(self, tmp_path, expiration):
        issues = self._issues(
            tmp_path,
            "global_settings:\n"
            "  ignore_paths:\n"
            "    - path: 'vendor/**'\n"
            "      reason: vendored\n"
            f"      expiration: '{expiration}'\n",
        )
        found = [
            i
            for i in self._at(issues, "global_settings.ignore_paths[0]")
            if "expired" in i.message
        ]
        assert len(found) == 1, issues
        (issue,) = found
        assert issue.severity == LintSeverity.WARNING
        assert expiration in issue.message
        assert issue.category != LintCategory.SUPPRESSION_EXPIRED, (
            "lint --fix removes SUPPRESSION_EXPIRED entries from suppressions by "
            "index, so an ignore path must not carry that category"
        )

    def test_live_ignore_path_is_not_reported(self, tmp_path):
        issues = self._issues(
            tmp_path,
            "global_settings:\n"
            "  ignore_paths:\n"
            "    - path: 'vendor/**'\n"
            "      reason: vendored\n"
            "      expiration: '2026-06-16'\n",
        )
        assert not [i for i in issues if "expir" in i.message], issues

    @pytest.mark.parametrize(
        "written",
        ["'TBD'", "'2026/06/30'", "2026-06-30"],
        ids=["word", "slashes", "unquoted"],
    )
    def test_malformed_ignore_path_date_is_an_error(self, tmp_path, written):
        issues = self._issues(
            tmp_path,
            "global_settings:\n"
            "  ignore_paths:\n"
            "    - path: 'vendor/**'\n"
            "      reason: vendored\n"
            f"      expiration: {written}\n",
        )
        errors = [
            i
            for i in self._at(issues, "global_settings.ignore_paths[0]")
            if i.severity == LintSeverity.ERROR and "YYYY-MM-DD" in i.message
        ]
        assert len(errors) == 1, issues

    def test_unquoted_suppression_date_is_an_error_not_a_crash(self, tmp_path):
        issues = self._issues(
            tmp_path,
            "global_settings:\n"
            "  suppressions:\n"
            "    - rule_id: B101\n"
            "      path: a.py\n"
            "      reason: r\n"
            "      expiration: 2026-06-30\n",
        )
        assert [
            i
            for i in self._at(issues, "global_settings.suppressions[0]")
            if i.severity == LintSeverity.ERROR and "YYYY-MM-DD" in i.message
        ], issues

    SCANNER_LISTS = [
        ("bandit", "excluded_paths", "Bandit excluded path"),
        ("checkov", "skip_path", "Checkov skip path"),
        ("syft", "exclude", "Syft exclude entry"),
    ]

    def _scanner_list_issues(self, tmp_path, scanner, field, expiration):
        issues = self._issues(
            tmp_path,
            "scanners:\n"
            f"  {scanner}:\n"
            "    options:\n"
            f"      {field}:\n"
            "        - path: vendor\n"
            "          reason: vendored\n"
            f"          expiration: {expiration}\n",
        )
        return self._at(issues, f"scanners.{scanner}.options.{field}[0]")

    @pytest.mark.parametrize("scanner,field,subject", SCANNER_LISTS)
    def test_expired_scanner_option_entry_is_reported(
        self, tmp_path, scanner, field, subject
    ):
        issues = self._scanner_list_issues(tmp_path, scanner, field, "'2026-06-01'")
        expired = [i for i in issues if "expired" in i.message]
        assert len(expired) == 1, issues
        assert expired[0].message.startswith(subject), expired[0].message

    @pytest.mark.parametrize("scanner,field,subject", SCANNER_LISTS)
    def test_malformed_scanner_option_date_is_an_error(
        self, tmp_path, scanner, field, subject
    ):
        issues = self._scanner_list_issues(tmp_path, scanner, field, "'TBD'")
        errors = [
            i
            for i in issues
            if i.severity == LintSeverity.ERROR and "YYYY-MM-DD" in i.message
        ]
        assert len(errors) == 1, issues
        # The model's message, as a scan prints it, names the entry by its place.
        assert errors[0].message.startswith(
            f"Invalid value at 'scanners.{scanner}.options.{field}[0].expiration': "
        ), errors[0].message


@pytest.mark.usefixtures("fixed_clock")
class TestWorkspacePolicy:
    """A workspace policy's ignore paths carry their expiration into each project."""

    @staticmethod
    def _workspace(tmp_path, policy_body):
        import json

        project = tmp_path / "api"
        (project / "vendor").mkdir(parents=True)
        workspace = tmp_path / "dev.code-workspace"
        workspace.write_text(json.dumps({"folders": [{"path": "api"}]}))
        ash_dir = tmp_path / ".ash"
        ash_dir.mkdir()
        (ash_dir / "ash-workspace.yaml").write_text(policy_body, encoding="utf-8")
        return workspace

    def _project_config(self, tmp_path, expiration):
        from automated_security_helper.workspace.execution import (
            ProjectScanSettings,
            _project_config_with_policy,
        )
        from automated_security_helper.workspace.resolver import resolve_workspace

        workspace = self._workspace(
            tmp_path,
            "workspace:\n"
            "  ignore_paths:\n"
            "    - path: 'api/vendor/*'\n"
            "      reason: third party\n"
            f"      expiration: '{expiration}'\n",
        )
        (project,) = resolve_workspace(workspace).projects
        assert [p.expiration for p in project.policy_ignore_paths] == [expiration]
        return project, _project_config_with_policy(
            project, ProjectScanSettings(output_dir=tmp_path / "out")
        )

    @pytest.mark.parametrize(
        "expiration,applies",
        [("2026-06-16", True), ("2026-06-15", False)],
        ids=["expires-tomorrow", "expires-today"],
    )
    def test_policy_ignore_path_stops_applying_on_its_expiration_day(
        self, tmp_path, expiration, applies
    ):
        project, config = self._project_config(tmp_path, expiration)
        context = PluginContext(
            source_dir=Path(project.path),
            output_dir=tmp_path / "out",
            config=config,
        )
        result = apply_suppressions_to_sarif(_sarif_with_one_finding(), context)
        assert (result.runs[0].results == []) is applies

    def test_policy_ignore_path_with_a_malformed_date_is_refused(self, tmp_path):
        from automated_security_helper.workspace.resolver import resolve_workspace

        workspace = self._workspace(
            tmp_path,
            "workspace:\n"
            "  ignore_paths:\n"
            "    - path: 'api/vendor/*'\n"
            "      reason: third party\n"
            "      expiration: '2026/06/30'\n",
        )
        with pytest.raises(WorkspaceDefinitionError) as excinfo:
            resolve_workspace(workspace)
        assert "YYYY-MM-DD" in str(excinfo.value)


class TestEveryReaderFiltersExpiredEntries:
    """Every read of ``global_settings.ignore_paths`` goes through the filter.

    A new consumer that read the list directly would apply expired entries
    again, silently. This walks the package source rather than restating the
    list of consumers, so adding one without the filter fails here.
    """

    PACKAGE = Path(__file__).resolve().parents[3] / "automated_security_helper"
    # Functions that read the list without applying it, by (module, function).
    NOT_APPLYING = {
        # Workspace mode appends the policy's entries to the project's own list.
        ("workspace/execution.py", "_project_config_with_policy"),
        # The scan-start warning about entries that expire within 30 days.
        (
            (
                "plugin_modules/ash_builtin/event_handlers/"
                "suppression_expiration_checker.py"
            ),
            "handle_suppression_expiration_check",
        ),
    }

    @staticmethod
    def _is_ignore_paths_read(node: ast.AST) -> bool:
        return (
            isinstance(node, ast.Attribute)
            and node.attr == "ignore_paths"
            and isinstance(node.ctx, ast.Load)
            and isinstance(node.value, ast.Attribute)
            and node.value.attr == "global_settings"
        )

    @staticmethod
    def _called_name(call: ast.Call) -> str | None:
        if isinstance(call.func, ast.Name):
            return call.func.id
        if isinstance(call.func, ast.Attribute):
            return call.func.attr
        return None

    def test_no_reader_bypasses_active_ignore_paths(self):
        offenders = []
        for path in sorted(self.PACKAGE.rglob("*.py")):
            rel = path.relative_to(self.PACKAGE).as_posix()
            tree = ast.parse(path.read_text(encoding="utf-8"))
            parents = {
                child: parent
                for parent in ast.walk(tree)
                for child in ast.iter_child_nodes(parent)
            }
            for node in ast.walk(tree):
                if not self._is_ignore_paths_read(node):
                    continue
                filtered = False
                function = None
                ancestor = parents.get(node)
                while ancestor is not None:
                    if (
                        isinstance(ancestor, ast.Call)
                        and self._called_name(ancestor) == "active_ignore_paths"
                    ):
                        filtered = True
                    if function is None and isinstance(
                        ancestor, (ast.FunctionDef, ast.AsyncFunctionDef)
                    ):
                        function = ancestor.name
                    ancestor = parents.get(ancestor)
                if filtered or (rel, function) in self.NOT_APPLYING:
                    continue
                offenders.append(f"{rel}:{node.lineno} (in {function})")
        assert offenders == [], (
            "these read global_settings.ignore_paths without active_ignore_paths(), "
            "so they would apply expired entries:\n" + "\n".join(offenders)
        )

    # Every model field typed with ignore-path entries, by (module, field), and
    # how each one is applied. A new field fails the test below until it is
    # classified here, which is the point: the author has to say where its
    # expiration is enforced.
    ENTRY_FIELDS = {
        # Read through active_ignore_paths() by the readers checked above.
        ("config/ash_config.py", "ignore_paths"): "global",
        # Workspace policy: copied into each project's global_settings.ignore_paths.
        ("config/ash_workspace_config.py", "ignore_paths"): "feeds-global",
        ("workspace/plan.py", "policy_ignore_paths"): "feeds-global",
        # Scanner options, turned into tool arguments in their own module.
        (
            "plugin_modules/ash_builtin/scanners/bandit_scanner.py",
            "excluded_paths",
        ): "scanner-option",
        (
            "plugin_modules/ash_builtin/scanners/checkov_scanner.py",
            "skip_path",
        ): "scanner-option",
        (
            "plugin_modules/ash_builtin/scanners/syft_scanner.py",
            "exclude",
        ): "scanner-option",
        # The list scan() was handed, kept so nothing_to_scan_reason answers from
        # the same package selection; _package_manifests filters it through
        # active_ignore_paths() at the read, so no entry is applied unfiltered.
        (
            "plugin_modules/ash_builtin/scanners/npm_audit_scanner.py",
            "_handed_ignore_paths",
        ): "filtered-at-read",
    }
    # Readers of a scanner option list that do not turn it into arguments.
    # None: bandit's _execute_scan does not save and restore the list.
    OPTION_NOT_APPLYING: set = set()

    def _entry_fields(self):
        found = set()
        for path in sorted(self.PACKAGE.rglob("*.py")):
            rel = path.relative_to(self.PACKAGE).as_posix()
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.ClassDef):
                    continue
                for stmt in node.body:
                    if (
                        isinstance(stmt, ast.AnnAssign)
                        and isinstance(stmt.target, ast.Name)
                        and "IgnorePathWithReason" in ast.unparse(stmt.annotation)
                    ):
                        found.add((rel, stmt.target.id))
        return found

    def test_every_entry_field_is_classified(self):
        found = self._entry_fields()
        # workspace/policy.py holds the resolved policy in a dataclass whose
        # ignore_paths is pushed into plan.policy_ignore_paths.
        found.discard(("workspace/policy.py", "ignore_paths"))
        assert found == set(self.ENTRY_FIELDS), (
            "a field typed with IgnorePathWithReason was added or removed; say in "
            "ENTRY_FIELDS how its expiration is enforced: "
            f"{sorted(found ^ set(self.ENTRY_FIELDS))}"
        )

    def test_filtered_at_read_fields_are_handed_only_to_a_filtering_function(self):
        """The ``filtered-at-read`` label is a claim about the code, so it is
        checked like the other two kinds: every read of the field is an
        argument of a call to a function in the same module, and that function
        passes the parameter receiving it through ``active_ignore_paths``. A
        read anywhere else, or a callee that stopped filtering, fails here."""
        offenders = []
        checked = 0
        for (rel, field_name), kind in sorted(self.ENTRY_FIELDS.items()):
            if kind != "filtered-at-read":
                continue
            tree = ast.parse((self.PACKAGE / rel).read_text(encoding="utf-8"))
            parents = {
                child: parent
                for parent in ast.walk(tree)
                for child in ast.iter_child_nodes(parent)
            }
            functions = {
                node.name: node
                for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
            reads = [
                node
                for node in ast.walk(tree)
                if isinstance(node, ast.Attribute)
                and node.attr == field_name
                and isinstance(node.ctx, ast.Load)
            ]
            assert reads, f"no read of {field_name} found in {rel}"
            for node in reads:
                call = parents.get(node)
                where = f"{rel}:{node.lineno} {field_name}"
                if not isinstance(call, ast.Call) or node not in call.args:
                    offenders.append(f"{where} is read outside a call's arguments")
                    continue
                callee = functions.get(self._called_name(call) or "")
                if callee is None:
                    offenders.append(f"{where} is handed to a function not in {rel}")
                    continue
                names = [arg.arg for arg in callee.args.args]
                if names and names[0] in ("self", "cls"):
                    names = names[1:]
                position = call.args.index(node)
                if position >= len(names):
                    offenders.append(f"{where} lands in no named parameter")
                    continue
                parameter = names[position]
                filtered = any(
                    isinstance(inner, ast.Call)
                    and self._called_name(inner) == "active_ignore_paths"
                    and any(
                        isinstance(name, ast.Name) and name.id == parameter
                        for argument in inner.args
                        for name in ast.walk(argument)
                    )
                    for inner in ast.walk(callee)
                )
                if not filtered:
                    offenders.append(
                        f"{where}: {callee.name} does not pass {parameter} "
                        "through active_ignore_paths()"
                    )
                checked += 1
        assert checked, "no filtered-at-read field was checked"
        assert offenders == [], "\n".join(offenders)

    def test_a_field_classified_filtered_at_read_is_filtered_where_it_is_read(self):
        """``filtered-at-read`` is a claim about the code: every read of the field
        is either inside an ``active_ignore_paths(...)`` call, or is an argument
        of a call to a function of the same module that calls it. Without this the
        classification in ENTRY_FIELDS is a comment, and a new read that applies
        the stored list as it is would pass."""
        claimed = [
            (rel, name)
            for (rel, name), how in sorted(self.ENTRY_FIELDS.items())
            if how == "filtered-at-read"
        ]
        # The control: the table holds a claim to check, and each field is read.
        assert claimed
        offenders = []
        for rel, name in claimed:
            tree = ast.parse((self.PACKAGE / rel).read_text(encoding="utf-8"))
            parents = {
                child: parent
                for parent in ast.walk(tree)
                for child in ast.iter_child_nodes(parent)
            }
            functions = {
                node.name: node
                for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
            reads = [
                node
                for node in ast.walk(tree)
                if isinstance(node, ast.Attribute)
                and node.attr == name
                and isinstance(node.ctx, ast.Load)
            ]
            assert reads, f"{rel} never reads {name}"
            for node in reads:
                filtered = False
                ancestor = parents.get(node)
                while ancestor is not None and not filtered:
                    if isinstance(ancestor, ast.Call):
                        called = self._called_name(ancestor)
                        filtered = called == "active_ignore_paths" or (
                            called in functions
                            and any(
                                isinstance(inner, ast.Call)
                                and self._called_name(inner) == "active_ignore_paths"
                                for inner in ast.walk(functions[called])
                            )
                        )
                    ancestor = parents.get(ancestor)
                if not filtered:
                    offenders.append(f"{rel}:{node.lineno} ({name})")
        assert offenders == [], (
            "these reads of a field classified filtered-at-read do not reach "
            "active_ignore_paths():\n" + "\n".join(offenders)
        )

    def test_scanner_option_lists_are_read_through_active_ignore_paths(self):
        offenders = []
        for (rel, field_name), kind in sorted(self.ENTRY_FIELDS.items()):
            if kind != "scanner-option":
                continue
            tree = ast.parse((self.PACKAGE / rel).read_text(encoding="utf-8"))
            parents = {
                child: parent
                for parent in ast.walk(tree)
                for child in ast.iter_child_nodes(parent)
            }
            reads = 0
            for node in ast.walk(tree):
                if not (
                    isinstance(node, ast.Attribute)
                    and node.attr == field_name
                    and isinstance(node.ctx, ast.Load)
                    and isinstance(node.value, ast.Attribute)
                    and node.value.attr == "options"
                ):
                    continue
                reads += 1
                filtered = False
                function = None
                ancestor = parents.get(node)
                while ancestor is not None:
                    if (
                        isinstance(ancestor, ast.Call)
                        and self._called_name(ancestor) == "active_ignore_paths"
                    ):
                        filtered = True
                    if function is None and isinstance(
                        ancestor, (ast.FunctionDef, ast.AsyncFunctionDef)
                    ):
                        function = ancestor.name
                    ancestor = parents.get(ancestor)
                if filtered or (rel, function) in self.OPTION_NOT_APPLYING:
                    continue
                offenders.append(f"{rel}:{node.lineno} options.{field_name}")
            assert reads, f"no read of options.{field_name} found in {rel}"
        assert offenders == [], (
            "these read a scanner's ignore-path option without "
            "active_ignore_paths():\n" + "\n".join(offenders)
        )
