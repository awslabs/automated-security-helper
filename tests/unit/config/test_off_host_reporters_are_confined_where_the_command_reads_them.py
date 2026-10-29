# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""``ash report`` and ``ash merge`` take an off-host reporter's settings from the overrides where they are read.

Stored results do not record which tree was scanned, so the commands hold a
``--config`` file to the rule that a reporter sending findings off the host runs,
and sends where it does, only as the defaults and ``--config-overrides`` say
(``config/reporter_trust.confine_off_host_reporters_to_overrides``). A reporter
is built from ``reporter_section``, which for such a reporter returns the
operator's view that ``resolve_config`` recorded (``AshConfig._operator_reporters``)
instead of the resolved ``reporters``. A ``--config`` file outside every tree that
extends a file inside one is in that view. The confinement therefore applies to the
view as well, so the section the reporter is built from is already the confined one
and the command reads it once.

A reporter that declares no ``destination_options`` cannot say which of its options
name where it sends, so its whole section is the operator's: the defaults and the
overrides, nothing from the file. And an ``options`` value that is not a mapping is
treated as empty, never as a place to keep a destination.

A scan keeps the operator's own chain files in that view on purpose, so its
confinement (``confine_declared_reporter_destinations`` without the commands'
step) leaves the view as it is.

The reporter classes below are defined here and are not registered with the plugin
manager; ``reporter_section`` and the confinement read only their declarations.
"""

from __future__ import annotations

import copy
import logging
from pathlib import Path
from typing import Any, ClassVar, Dict, List, Literal, Optional, Tuple

import pytest
from pydantic import Field

from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
    off_host_reporter_refused,
    reset_unenabled_off_host_section_warnings,
    warn_off_host_section_without_enabled,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.operator_only_options import reporter_section
from automated_security_helper.config.reporter_trust import (
    confine_declared_reporter_destinations,
    confine_off_host_reporters_to_overrides,
    confine_reporter_destinations,
)
from automated_security_helper.config.resolve_config import apply_config_overrides
from automated_security_helper.config.untrusted_source import REPORT_CONFIG_FILE
from automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter import (
    S3Reporter,
)
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit

#: A path nothing reads: the confinement only names it in its warning.
CONFIG_FILE = Path("/elsewhere/.ash.yaml")

FILE_BUCKET = "file-bucket"
FILE_REGION = "eu-west-1"
OPERATOR_BUCKET = "operator-bucket"
OPERATOR_REGION = "us-west-2"


class _TokenOptions(ReporterOptionsBase):
    token: str = Field("", alias="apiToken")
    region: str = "default-region"
    title: str = "default title"


class _TokenConfig(ReporterPluginConfigBase):
    name: Literal["token-offhost"] = "token-offhost"
    enabled: bool = False
    options: _TokenOptions = _TokenOptions()


class _TokenOffHostReporter(ReporterPluginBase[_TokenConfig]):
    """Off-host, and it names the options that say where it sends."""

    sends_off_host: ClassVar[bool] = True
    destination_options: ClassVar[Tuple[str, ...]] = ("token", "region")

    def report(self, model):
        return None


class _QuietOptions(ReporterOptionsBase):
    endpoint: str = "https://default.invalid/"
    title: str = "default title"


class _QuietConfig(ReporterPluginConfigBase):
    name: Literal["quiet-offhost"] = "quiet-offhost"
    enabled: bool = False
    options: _QuietOptions = _QuietOptions()


class _QuietOffHostReporter(ReporterPluginBase[_QuietConfig]):
    """Off-host, and it declares no destination options."""

    sends_off_host: ClassVar[bool] = True

    def report(self, model):
        return None


class _LocalConfig(ReporterPluginConfigBase):
    name: Literal["local-report"] = "local-report"
    options: _QuietOptions = _QuietOptions()


class _LocalReporter(ReporterPluginBase[_LocalConfig]):
    """Writes only a local file."""

    def report(self, model):
        return None


@pytest.fixture
def ash_log():
    records: List[logging.LogRecord] = []

    class _Collect(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _Collect(level=logging.WARNING)
    previous = ASH_LOGGER.level
    ASH_LOGGER.addHandler(handler)
    ASH_LOGGER.setLevel(logging.DEBUG)
    try:
        yield records
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(previous)


def _config(
    resolved: Dict[str, Any],
    view: Optional[Dict[str, Any]] = None,
    overrides: Tuple[str, ...] = (),
) -> AshConfig:
    """A resolved config, with ``view`` recorded as the operator's view when given.

    ``resolve_config`` applies the operator's overrides to both, so they are
    applied to both here.
    """
    config = AshConfig.model_validate({"reporters": copy.deepcopy(resolved)})
    recorded = None
    if view is not None:
        recorded = AshConfig.model_validate({"reporters": copy.deepcopy(view)})
    if overrides:
        config = apply_config_overrides(config, list(overrides))
        if recorded is not None:
            recorded = apply_config_overrides(recorded, list(overrides))
    config._operator_reporters = recorded
    return config


def _as_ash_report_confines(
    config: AshConfig, classes: List[type], overrides: Tuple[str, ...] = ()
) -> None:
    """The two confinement calls ``ash report`` makes, in its order."""
    confine_off_host_reporters_to_overrides(
        config, [CONFIG_FILE], list(overrides), REPORT_CONFIG_FILE
    )
    confine_declared_reporter_destinations(config, classes, source=REPORT_CONFIG_FILE)


def _built_from(config: AshConfig, reporter_class: type) -> Any:
    """The section ``ash report`` builds the reporter from."""
    return reporter_section(config, reporter_class)


def _options(section: Any) -> Dict[str, Any]:
    options = (section or {}).get("options")
    return options if isinstance(options, dict) else {}


# ---------------------------------------------------------------------------
# A built-in reporter that declares its destinations (S3): the operator's view
# ---------------------------------------------------------------------------

#: Each row is an operator view (and the resolved section, written the same way)
#: that names a destination. After the commands' confinement none of it reaches
#: the reporter, whatever shape it is written in.
S3_VIEWS = {
    "both-destinations": {
        "enabled": True,
        "options": {
            "bucket_name": FILE_BUCKET,
            "aws_region": FILE_REGION,
            "file_format": "yaml",
        },
    },
    "dashed-spelling": {
        "enabled": True,
        "options": {"bucket-name": FILE_BUCKET, "aws-region": FILE_REGION},
    },
    "enabled-only": {"enabled": True},
    "options-is-a-string": {
        "enabled": True,
        "options": f"bucket_name={FILE_BUCKET}",
    },
    "options-is-a-list-of-mappings": {
        "enabled": True,
        "options": [{"bucket_name": FILE_BUCKET}, {"aws_region": FILE_REGION}],
    },
    "options-is-zero": {"enabled": True, "options": 0},
}


class TestTheViewIsConfinedAtTheSource:
    @pytest.mark.parametrize("name", sorted(S3_VIEWS))
    def test_no_destination_the_view_holds_reaches_the_reporter(self, name):
        """The view and the resolved section both name a destination; neither is used.

        ``options`` that is not a mapping is dropped with the rest, not carried
        through as it is (the reporter's own model would refuse it, but the
        section is also what a later reader sees).
        """
        section = S3_VIEWS[name]
        config = _config({"s3": dict(section)}, view={"s3": dict(section)})
        assert config._operator_reporters is not None

        _as_ash_report_confines(config, [S3Reporter])

        built = _built_from(config, S3Reporter)
        assert off_host_reporter_refused(S3Reporter, built), built
        assert FILE_BUCKET not in repr(built), built
        assert FILE_REGION not in repr(built), built

    def test_a_setting_that_is_not_a_destination_is_kept(self):
        section = S3_VIEWS["both-destinations"]
        config = _config({"s3": dict(section)}, view={"s3": dict(section)})

        _as_ash_report_confines(config, [S3Reporter])

        built = _built_from(config, S3Reporter)
        assert _options(built)["file_format"] == "yaml", built
        assert "bucket_name" not in _options(built), built

    @pytest.mark.parametrize(
        "resolved",
        [{}, {"s3": None}, {"s3": {"options": 0}}],
        ids=["confined-section-absent", "confined-section-none", "options-zero"],
    )
    def test_the_view_is_confined_whatever_the_resolved_section_is(self, resolved):
        """The confined section may be absent, null or malformed; the view is the source."""
        view = {"s3": dict(S3_VIEWS["both-destinations"])}
        config = _config(resolved, view=view)

        _as_ash_report_confines(config, [S3Reporter])

        built = _built_from(config, S3Reporter)
        assert FILE_BUCKET not in repr(built), built
        assert FILE_REGION not in repr(built), built

    @pytest.mark.parametrize(
        "view",
        [{"s3": None}, {}],
        ids=["operator-mapping-none", "operator-section-absent"],
    )
    def test_an_empty_view_leaves_the_reporter_refused(self, view):
        config = _config({"s3": dict(S3_VIEWS["both-destinations"])}, view=view)

        _as_ash_report_confines(config, [S3Reporter])

        assert off_host_reporter_refused(S3Reporter, _built_from(config, S3Reporter))

    def test_the_overrides_still_turn_it_on_and_aim_it(self):
        """The file also sets a key prefix the overrides do not; only the overrides' values remain."""
        overrides = (
            "reporters.s3.enabled=true",
            f"reporters.s3.options.bucket_name={OPERATOR_BUCKET}",
            f"reporters.s3.options.aws_region={OPERATOR_REGION}",
        )
        file_section = {
            "enabled": True,
            "options": {
                "bucket_name": FILE_BUCKET,
                "aws_region": FILE_REGION,
                "key_prefix": "file-prefix/",
            },
        }
        config = _config(
            {"s3": dict(file_section)},
            view={"s3": dict(file_section)},
            overrides=overrides,
        )

        _as_ash_report_confines(config, [S3Reporter], overrides)

        built = _built_from(config, S3Reporter)
        assert not off_host_reporter_refused(S3Reporter, built), built
        assert _options(built)["bucket_name"] == OPERATOR_BUCKET
        assert _options(built)["aws_region"] == OPERATOR_REGION
        assert "file-prefix" not in repr(built), built
        assert FILE_BUCKET not in repr(built), built

    def test_one_warning_names_what_was_ignored_once(self, ash_log):
        """The view repeats what the resolved section holds; it is named once."""
        section = S3_VIEWS["both-destinations"]
        config = _config({"s3": dict(section)}, view={"s3": dict(section)})

        confine_off_host_reporters_to_overrides(
            config, [CONFIG_FILE], [], REPORT_CONFIG_FILE
        )

        [warning] = [
            r.getMessage() for r in ash_log if r.getMessage().startswith("Ignoring ")
        ]
        assert warning.count("reporters.s3.options.bucket_name") == 1, warning
        assert warning.count("reporters.s3.enabled") == 1, warning


class TestControlsThatHoldWithoutTheChange:
    def test_with_no_view_the_reporter_is_built_from_the_confined_section(self):
        section = S3_VIEWS["both-destinations"]
        config = _config({"s3": dict(section)}, view=None)

        _as_ash_report_confines(config, [S3Reporter])

        built = _built_from(config, S3Reporter)
        assert built == config.get_plugin_config(
            plugin_type="reporter", plugin_name="s3"
        )
        assert off_host_reporter_refused(S3Reporter, built)
        assert FILE_BUCKET not in repr(built), built

    def test_a_scan_keeps_the_operators_chain_file_destinations(self):
        """No command step ran: the view is the operator's own, and it stays whole.

        A scan's operator view holds what the operator's chain files wrote,
        which the trusted base does not, so confining it there would drop a
        destination the operator chose.
        """
        view_section = {
            "enabled": True,
            "options": {"apiToken": "chain-token", "region": "chain-region"},
        }
        config = _config(
            {"token-offhost": {"enabled": False}},
            view={"token-offhost": view_section},
        )
        view = config._operator_reporters
        config._trusted_reporter_base = AshConfig()
        config._in_tree_config_files = (CONFIG_FILE,)

        confine_declared_reporter_destinations(config, [_TokenOffHostReporter])

        assert config._operator_reporters is view
        built = _built_from(config, _TokenOffHostReporter)
        assert built["options"]["apiToken"] == "chain-token", built
        assert built["options"]["region"] == "chain-region", built
        assert not off_host_reporter_refused(_TokenOffHostReporter, built)

    def test_a_local_reporters_section_is_kept(self):
        section = {"enabled": True, "options": {"endpoint": "https://file.invalid/"}}
        config = _config({"local-report": dict(section)}, view={})

        _as_ash_report_confines(config, [_LocalReporter])

        assert _built_from(config, _LocalReporter) == section


# ---------------------------------------------------------------------------
# A plugin reporter that declares its destinations
# ---------------------------------------------------------------------------


class TestADeclaredReportersViewIsConfined:
    def test_an_aliased_destination_in_the_view_does_not_reach_the_reporter(self):
        section = {
            "enabled": True,
            "options": {
                "apiToken": "chain-token",
                "region": "chain-region",
                "title": "chain title",
            },
        }
        config = _config(
            {"token-offhost": dict(section)}, view={"token-offhost": dict(section)}
        )

        _as_ash_report_confines(config, [_TokenOffHostReporter])

        built = _built_from(config, _TokenOffHostReporter)
        assert off_host_reporter_refused(_TokenOffHostReporter, built), built
        assert "chain-token" not in repr(built), built
        assert "chain-region" not in repr(built), built
        assert _options(built)["title"] == "chain title", built


# ---------------------------------------------------------------------------
# An off-host plugin reporter that declares no destination options
# ---------------------------------------------------------------------------

FILE_ENDPOINT = "https://file.invalid/"
OVERRIDE_ENDPOINT = "https://override.invalid/"

QUIET_SECTION = {
    "enabled": True,
    "options": {"endpoint": FILE_ENDPOINT, "title": "file title"},
}


class TestAnOffHostReporterWithNoDeclaredDestinations:
    @pytest.mark.parametrize("with_view", [False, True], ids=["no-view", "with-view"])
    def test_the_files_settings_do_not_enable_it_or_reach_it(self, with_view):
        view = {"quiet-offhost": dict(QUIET_SECTION)} if with_view else None
        config = _config({"quiet-offhost": dict(QUIET_SECTION)}, view=view)

        _as_ash_report_confines(config, [_QuietOffHostReporter])

        built = _built_from(config, _QuietOffHostReporter)
        assert off_host_reporter_refused(_QuietOffHostReporter, built), built
        assert FILE_ENDPOINT not in repr(built), built
        assert "file title" not in repr(built), built

    @pytest.mark.parametrize("with_view", [False, True], ids=["no-view", "with-view"])
    def test_an_override_that_enables_it_gives_it_the_overrides_section_alone(
        self, with_view
    ):
        overrides = ("reporters.quiet-offhost.enabled=true",)
        view = {"quiet-offhost": dict(QUIET_SECTION)} if with_view else None
        config = _config(
            {"quiet-offhost": dict(QUIET_SECTION)}, view=view, overrides=overrides
        )

        _as_ash_report_confines(config, [_QuietOffHostReporter], overrides)

        built = _built_from(config, _QuietOffHostReporter)
        assert not off_host_reporter_refused(_QuietOffHostReporter, built), built
        assert FILE_ENDPOINT not in repr(built), built
        assert "file title" not in repr(built), built

    def test_an_override_that_aims_it_is_the_only_option_it_gets(self):
        overrides = (
            "reporters.quiet-offhost.enabled=true",
            f"reporters.quiet-offhost.options.endpoint={OVERRIDE_ENDPOINT}",
        )
        config = _config(
            {"quiet-offhost": dict(QUIET_SECTION)},
            view={"quiet-offhost": dict(QUIET_SECTION)},
            overrides=overrides,
        )

        _as_ash_report_confines(config, [_QuietOffHostReporter], overrides)

        built = _built_from(config, _QuietOffHostReporter)
        assert not off_host_reporter_refused(_QuietOffHostReporter, built), built
        assert _options(built) == {"endpoint": OVERRIDE_ENDPOINT}, built

    def test_the_plugin_is_named_in_the_warning(self, ash_log):
        config = _config({"quiet-offhost": dict(QUIET_SECTION)})

        _as_ash_report_confines(config, [_QuietOffHostReporter])

        warnings = [
            r.getMessage() for r in ash_log if r.getMessage().startswith("Ignoring ")
        ]
        assert any("reporters.quiet-offhost" in w for w in warnings), warnings
        assert not any(FILE_ENDPOINT in w for w in warnings), warnings

    def test_a_scan_builds_it_from_the_view_as_before(self):
        """No command step ran: the resolved section is left to ``reporter_section``."""
        config = _config(
            {"quiet-offhost": dict(QUIET_SECTION)},
            view={"quiet-offhost": {"enabled": True}},
        )
        config._trusted_reporter_base = AshConfig()
        config._in_tree_config_files = (CONFIG_FILE,)

        confine_declared_reporter_destinations(config, [_QuietOffHostReporter])

        resolved = config.get_plugin_config(
            plugin_type="reporter", plugin_name="quiet-offhost"
        )
        assert resolved == QUIET_SECTION
        assert _built_from(config, _QuietOffHostReporter) == {"enabled": True}


class TestTheSectionIsNamedOnceWhenTheReporterIsBuilt:
    """The command's warning stands for a section it replaced whole.

    ``reporter_section`` warns once per reporter when the section it finds in the
    resolved config is not inside the operator's view. After the command has
    replaced the whole section of a reporter that lists no destinations, what is
    left is the trusted base's, and a second warning, with the remedy for a scan,
    would repeat the first one and contradict its remedy.
    """

    @staticmethod
    def _named(ash_log) -> List[str]:
        return [
            r.getMessage()
            for r in ash_log
            if r.getMessage().startswith("Ignoring ")
            and "reporters.quiet-offhost" in r.getMessage()
        ]

    def test_building_the_reporter_adds_no_second_warning(self, ash_log):
        config = _config({"quiet-offhost": dict(QUIET_SECTION)}, view={})

        _as_ash_report_confines(config, [_QuietOffHostReporter])
        reporter_section(config, _QuietOffHostReporter)

        named = self._named(ash_log)
        assert len(named) == 1, named
        assert "--config-overrides" in named[0], named

    def test_a_scan_still_gets_the_warning_when_the_reporter_is_built(self, ash_log):
        """Control: no command step ran, so ``reporter_section`` names the section."""
        config = _config({"quiet-offhost": dict(QUIET_SECTION)}, view={})
        config._trusted_reporter_base = AshConfig()
        config._in_tree_config_files = (CONFIG_FILE,)

        confine_declared_reporter_destinations(config, [_QuietOffHostReporter])
        reporter_section(config, _QuietOffHostReporter)

        assert len(self._named(ash_log)) == 1, self._named(ash_log)


FILE_TOKEN = "file-token"


class TestASettingIsNamedOnceWhateverSpellingEachCopyHolds:
    """One setting in two copies of the config is one name in the warning.

    A workspace project's config has the operator's config merged over it, and a
    section both write is kept under the operator's spelling, so the resolved
    config and the operator view can hold the section under a spelling the file
    did not write. The warning quotes it as the file wrote it
    (``_in_tree_reporter_keys``, recorded on the config only), so both copies are
    quoted with those spellings and the duplicate collapses.
    """

    def test_the_resolved_section_and_the_view_name_one_setting_once(self, ash_log):
        section = {"options": {"apiToken": FILE_TOKEN}}
        config = _config(
            {"token-offhost": copy.deepcopy(section)},
            view={"token-offhost": copy.deepcopy(section)},
        )
        config._in_tree_reporter_keys = ("token_offhost",)

        _as_ash_report_confines(config, [_TokenOffHostReporter])

        [warning] = [
            r.getMessage() for r in ash_log if r.getMessage().startswith("Ignoring ")
        ]
        assert warning.count("options.apiToken") == 1, warning
        assert "reporters.token_offhost.options.apiToken" in warning, warning
        assert "reporters.token-offhost" not in warning, warning

    def test_a_section_the_file_spelled_as_the_config_holds_it_is_named_once(
        self, ash_log
    ):
        """Control: with one spelling in every copy there is nothing to collapse."""
        section = {"options": {"apiToken": FILE_TOKEN}}
        config = _config(
            {"token-offhost": copy.deepcopy(section)},
            view={"token-offhost": copy.deepcopy(section)},
        )
        config._in_tree_reporter_keys = ("token-offhost",)

        _as_ash_report_confines(config, [_TokenOffHostReporter])

        [warning] = [
            r.getMessage() for r in ash_log if r.getMessage().startswith("Ignoring ")
        ]
        assert warning.count("reporters.token-offhost.options.apiToken") == 1, warning


#: Each built-in reporter's section key as the operator's config spells it, and a
#: spelling of the same reporter that a file could write instead. The lookup reads
#: both as one section.
BUILT_IN_SPELLINGS = {
    "aws-security-hub": "aws_security_hub",
    "bedrock-summary-reporter": "bedrock_summary_reporter",
    "cloudwatch-logs": "cloudwatch_logs",
    "s3": "S3",
}


class TestABuiltInSettingIsNamedOnceUnderTheFilesSpelling:
    """``ash report`` and ``ash merge`` quote a built-in reporter as the file wrote it.

    The command confines the four built-in reporters in its own step
    (``confine_off_host_reporters_to_overrides``), before any plugin module is
    loaded. The spellings the files wrote were recorded on the config earlier and
    have to be in use while that step names what it ignored, not put back after
    it: otherwise one setting held in two copies of the config under two
    spellings is named twice, and a setting held under one spelling is named
    under the operator's instead of the file's.
    """

    @staticmethod
    def _warning(ash_log) -> str:
        [warning] = [
            r.getMessage() for r in ash_log if r.getMessage().startswith("Ignoring ")
        ]
        return warning

    @pytest.mark.parametrize("operator_key", sorted(BUILT_IN_SPELLINGS))
    def test_a_setting_in_both_copies_is_named_under_the_files_spelling(
        self, operator_key, ash_log
    ):
        file_key = BUILT_IN_SPELLINGS[operator_key]
        section = {"options": {"aws_region": FILE_REGION}}
        config = _config(
            {operator_key: copy.deepcopy(section)},
            view={operator_key: copy.deepcopy(section)},
        )
        config._in_tree_reporter_keys = (file_key,)

        _as_ash_report_confines(config, [])

        warning = self._warning(ash_log)
        assert warning.count("options.aws_region") == 1, warning
        assert f"reporters.{file_key}.options.aws_region" in warning, warning
        assert f"reporters.{operator_key}." not in warning, warning

    @pytest.mark.parametrize("operator_key", sorted(BUILT_IN_SPELLINGS))
    def test_two_copies_under_two_spellings_are_named_once(self, operator_key, ash_log):
        file_key = BUILT_IN_SPELLINGS[operator_key]
        section = {"options": {"aws_region": FILE_REGION}}
        config = _config(
            {operator_key: copy.deepcopy(section)},
            view={file_key: copy.deepcopy(section)},
        )
        config._in_tree_reporter_keys = (file_key,)

        _as_ash_report_confines(config, [])

        warning = self._warning(ash_log)
        assert warning.count("options.aws_region") == 1, warning
        assert f"reporters.{file_key}.options.aws_region" in warning, warning
        assert f"reporters.{operator_key}." not in warning, warning

    @pytest.mark.parametrize("operator_key", sorted(BUILT_IN_SPELLINGS))
    def test_a_setting_spelled_the_same_everywhere_is_named_once(
        self, operator_key, ash_log
    ):
        """Control: with one spelling in every copy there is nothing to collapse."""
        section = {"options": {"aws_region": FILE_REGION}}
        config = _config(
            {operator_key: copy.deepcopy(section)},
            view={operator_key: copy.deepcopy(section)},
        )
        config._in_tree_reporter_keys = (operator_key,)

        _as_ash_report_confines(config, [])

        warning = self._warning(ash_log)
        assert warning.count("options.aws_region") == 1, warning
        assert f"reporters.{operator_key}.options.aws_region" in warning, warning

    def test_with_no_recorded_spelling_the_section_is_named_as_it_is_held(
        self, ash_log
    ):
        """Control: a config no file wrote a section of is quoted by its own key."""
        section = {"options": {"aws_region": FILE_REGION}}
        config = _config(
            {"aws-security-hub": copy.deepcopy(section)},
            view={"aws-security-hub": copy.deepcopy(section)},
        )

        _as_ash_report_confines(config, [])

        warning = self._warning(ash_log)
        assert "reporters.aws-security-hub.options.aws_region" in warning, warning

    def test_the_recorded_spellings_are_the_same_after_the_step(self):
        """The step adds no spelling of its own and leaves the recorded ones as they were."""
        section = {"options": {"aws_region": FILE_REGION}}
        config = _config(
            {"aws-security-hub": copy.deepcopy(section)},
            view={"aws-security-hub": copy.deepcopy(section)},
        )
        config._in_tree_reporter_keys = ("aws_security_hub", "s3")

        confine_off_host_reporters_to_overrides(
            config, [CONFIG_FILE], [], REPORT_CONFIG_FILE
        )

        assert config._in_tree_reporter_keys == ("aws_security_hub", "s3")


MALFORMED_OPTIONS = f"bucket_name={FILE_BUCKET}"


class TestAMalformedOptionsValueInAScan:
    """A scan leaves the resolved section as written, whatever the base sets.

    A reporter built from that section meets the value in its model, which refuses
    it. A reporter that sends findings off the host is built from the operator
    view instead, so these tests check the stored value only.

    An ``options`` value that is not a mapping names no option. A scan used to
    replace it with the trusted base's destinations when the base set any, with no
    warning and without the file's other options, and to leave it in place when the
    base set none, so whether the reporter was built depended on an unrelated
    setting of the operator's. ``ash report`` and ``ash merge`` name it and drop it.
    """

    @staticmethod
    def _options_after_a_scan(trusted_sets_a_destination: bool) -> object:
        trusted = AshConfig()
        if trusted_sets_a_destination:
            trusted = apply_config_overrides(
                trusted, [f"reporters.s3.options.bucket_name={OPERATOR_BUCKET}"]
            )
        config = _config({"s3": {"enabled": True, "options": MALFORMED_OPTIONS}})

        confine_reporter_destinations(config, trusted, [], [CONFIG_FILE])

        return config.reporters.__pydantic_extra__["s3"]["options"]

    @pytest.mark.parametrize(
        "trusted_sets_a_destination",
        [True, False],
        ids=["the-base-sets-a-destination", "the-base-sets-none"],
    )
    def test_it_is_left_as_it_was_written(self, trusted_sets_a_destination):
        options = self._options_after_a_scan(trusted_sets_a_destination)

        assert options == MALFORMED_OPTIONS, options

    def test_a_command_names_it_and_drops_it(self, ash_log):
        """Control: a command that takes the settings from the overrides replaces it."""
        config = _config({"s3": {"enabled": True, "options": MALFORMED_OPTIONS}})

        confine_off_host_reporters_to_overrides(
            config, [CONFIG_FILE], [], REPORT_CONFIG_FILE
        )

        [warning] = [
            r.getMessage() for r in ash_log if r.getMessage().startswith("Ignoring ")
        ]
        assert "reporters.s3.options" in warning, warning
        options = config.reporters.__pydantic_extra__["s3"]["options"]
        assert isinstance(options, dict), options


# ---------------------------------------------------------------------------
# A plugin reporter that declares its destinations and is on by default
# ---------------------------------------------------------------------------


class _DefaultOnConfig(ReporterPluginConfigBase):
    name: Literal["default-on-offhost"] = "default-on-offhost"
    enabled: bool = True
    options: _QuietOptions = _QuietOptions()


class _DefaultOnOffHostReporter(ReporterPluginBase[_DefaultOnConfig]):
    """Off-host, on by default, and it names the option that says where it sends."""

    sends_off_host: ClassVar[bool] = True
    destination_options: ClassVar[Tuple[str, ...]] = ("endpoint",)

    def report(self, model):
        return None


class _LocalDefaultOnConfig(ReporterPluginConfigBase):
    name: Literal["default-on-local"] = "default-on-local"
    enabled: bool = True
    options: _QuietOptions = _QuietOptions()


class _LocalDefaultOnReporter(ReporterPluginBase[_LocalDefaultOnConfig]):
    """Names where it writes, sends nothing off the host, and is on by default."""

    destination_options: ClassVar[Tuple[str, ...]] = ("endpoint",)

    def report(self, model):
        return None


DEFAULT_ON_SECTION = {
    "enabled": True,
    "options": {"endpoint": FILE_ENDPOINT, "title": "file title"},
}


class TestAReporterThatIsOnByDefaultIsNotEnabledByAFile:
    """Its own default does not count as the operator's choice.

    A reporter that sends findings off the host runs only when its section says
    ``enabled: true`` (``off_host_reporter_refused``). The trusted base is the
    defaults and the overrides, and for this reporter it sets no ``enabled`` unless
    an override does, so a ``true`` in the file would otherwise match the reporter's
    own default and be kept.
    """

    @pytest.mark.parametrize("with_view", [False, True], ids=["no-view", "with-view"])
    def test_the_files_enabled_true_does_not_run_it(self, with_view):
        view = {"default-on-offhost": dict(DEFAULT_ON_SECTION)} if with_view else None
        config = _config({"default-on-offhost": dict(DEFAULT_ON_SECTION)}, view=view)

        _as_ash_report_confines(config, [_DefaultOnOffHostReporter])

        built = _built_from(config, _DefaultOnOffHostReporter)
        assert off_host_reporter_refused(_DefaultOnOffHostReporter, built), built
        assert FILE_ENDPOINT not in repr(built), built

    @pytest.mark.parametrize("with_view", [False, True], ids=["no-view", "with-view"])
    def test_the_files_enabled_false_does_not_run_it_either(self, with_view):
        section = {**DEFAULT_ON_SECTION, "enabled": False}
        view = {"default-on-offhost": dict(section)} if with_view else None
        config = _config({"default-on-offhost": dict(section)}, view=view)

        _as_ash_report_confines(config, [_DefaultOnOffHostReporter])

        built = _built_from(config, _DefaultOnOffHostReporter)
        assert off_host_reporter_refused(_DefaultOnOffHostReporter, built), built

    def test_a_section_with_no_enabled_leaves_it_refused(self):
        section = {"options": dict(DEFAULT_ON_SECTION["options"])}
        config = _config({"default-on-offhost": dict(section)})

        _as_ash_report_confines(config, [_DefaultOnOffHostReporter])

        built = _built_from(config, _DefaultOnOffHostReporter)
        assert off_host_reporter_refused(_DefaultOnOffHostReporter, built), built
        assert FILE_ENDPOINT not in repr(built), built

    @pytest.mark.parametrize("with_view", [False, True], ids=["no-view", "with-view"])
    def test_an_override_that_enables_it_runs_it_at_the_default(self, with_view):
        overrides = ("reporters.default-on-offhost.enabled=true",)
        view = {"default-on-offhost": dict(DEFAULT_ON_SECTION)} if with_view else None
        config = _config(
            {"default-on-offhost": dict(DEFAULT_ON_SECTION)},
            view=view,
            overrides=overrides,
        )

        _as_ash_report_confines(config, [_DefaultOnOffHostReporter], overrides)

        built = _built_from(config, _DefaultOnOffHostReporter)
        assert not off_host_reporter_refused(_DefaultOnOffHostReporter, built), built
        assert FILE_ENDPOINT not in repr(built), built
        # Not a destination option: the file's value applies.
        assert _options(built)["title"] == "file title", built

    def test_an_override_that_turns_it_off_wins_over_the_files_enabled_true(self):
        overrides = ("reporters.default-on-offhost.enabled=false",)
        config = _config(
            {"default-on-offhost": dict(DEFAULT_ON_SECTION)}, overrides=overrides
        )

        _as_ash_report_confines(config, [_DefaultOnOffHostReporter], overrides)

        built = _built_from(config, _DefaultOnOffHostReporter)
        assert off_host_reporter_refused(_DefaultOnOffHostReporter, built), built

    def test_the_warning_names_the_enabled_the_file_set(self, ash_log):
        config = _config({"default-on-offhost": dict(DEFAULT_ON_SECTION)})

        _as_ash_report_confines(config, [_DefaultOnOffHostReporter])

        warnings = [
            r.getMessage() for r in ash_log if r.getMessage().startswith("Ignoring ")
        ]
        assert any("reporters.default-on-offhost.enabled" in w for w in warnings), (
            warnings
        )

    def test_the_files_enabled_is_replaced_by_false_and_not_left_out(self):
        """An off-host reporter's section says ``enabled: false`` once the file's is ignored."""
        config = _config({"default-on-offhost": dict(DEFAULT_ON_SECTION)})

        _as_ash_report_confines(config, [_DefaultOnOffHostReporter])

        built = _built_from(config, _DefaultOnOffHostReporter)
        assert built.get("enabled") is False, built
        assert FILE_ENDPOINT not in repr(built), built

    def test_a_merge_does_not_name_the_section_as_setting_options_without_enabled(
        self, ash_log
    ):
        """``ash merge`` names an off-host section that sets options and no ``enabled``.

        That warning says the reporter is disabled by default. For a reporter that
        is on by default the section would only lack ``enabled`` because the file's
        was dropped, and the warning for the file's ``enabled`` already said so, so
        the second one would contradict it.
        """
        config = _config({"default-on-offhost": dict(DEFAULT_ON_SECTION)})
        _as_ash_report_confines(config, [_DefaultOnOffHostReporter])
        built = _built_from(config, _DefaultOnOffHostReporter)
        ash_log.clear()

        reset_unenabled_off_host_section_warnings()
        try:
            warn_off_host_section_without_enabled(_DefaultOnOffHostReporter, built)
        finally:
            reset_unenabled_off_host_section_warnings()

        named = [
            r.getMessage() for r in ash_log if "sets options but not" in r.getMessage()
        ]
        assert not named, named

    def test_the_files_enabled_false_is_not_named_as_ignored(self, ash_log):
        """The section keeps the ``false`` the file wrote, so nothing it wrote is ignored."""
        section = {**DEFAULT_ON_SECTION, "enabled": False}
        config = _config({"default-on-offhost": dict(section)})

        _as_ash_report_confines(config, [_DefaultOnOffHostReporter])

        [warning] = [
            r.getMessage() for r in ash_log if r.getMessage().startswith("Ignoring ")
        ]
        assert "reporters.default-on-offhost.options.endpoint" in warning, warning
        assert "reporters.default-on-offhost.enabled" not in warning, warning
        built = _built_from(config, _DefaultOnOffHostReporter)
        assert built.get("enabled") is False, built

    def test_a_second_pass_does_not_name_the_enabled_it_wrote(self, ash_log):
        """Control: the ``false`` the first pass wrote is not the file's, so it is not named."""
        config = _config({"default-on-offhost": dict(DEFAULT_ON_SECTION)})
        _as_ash_report_confines(config, [_DefaultOnOffHostReporter])
        ash_log.clear()

        confine_declared_reporter_destinations(
            config, [_DefaultOnOffHostReporter], source=REPORT_CONFIG_FILE
        )

        named = [
            r.getMessage()
            for r in ash_log
            if "reporters.default-on-offhost.enabled" in r.getMessage()
        ]
        assert not named, named

    @pytest.mark.parametrize("enabled", [True, False], ids=["true", "false"])
    def test_a_local_reporter_that_is_on_by_default_stays_on(self, enabled, ash_log):
        """Control: only a reporter that sends findings off the host needs an opt-in.

        A local reporter runs with its file's ``enabled: true`` as it always did, so
        no warning says that value was ignored. (A file's ``false`` is still turned
        back on and named: the trusted base wants it on.)
        """
        section = {**DEFAULT_ON_SECTION, "enabled": enabled}
        config = _config({"default-on-local": dict(section)})

        _as_ash_report_confines(config, [_LocalDefaultOnReporter])

        built = _built_from(config, _LocalDefaultOnReporter)
        assert (built or {}).get("enabled", True) is True, built
        assert not off_host_reporter_refused(_LocalDefaultOnReporter, built), built
        assert FILE_ENDPOINT not in repr(built), built
        named = [
            r.getMessage()
            for r in ash_log
            if "reporters.default-on-local.enabled" in r.getMessage()
        ]
        assert bool(named) is (enabled is False), named

    def test_a_scan_keeps_the_section_as_before(self):
        """Control: no command step ran, so the scan's own rule applies."""
        config = _config(
            {"default-on-offhost": dict(DEFAULT_ON_SECTION)},
            view={"default-on-offhost": {"enabled": True}},
        )
        config._trusted_reporter_base = AshConfig()
        config._in_tree_config_files = (CONFIG_FILE,)

        confine_declared_reporter_destinations(config, [_DefaultOnOffHostReporter])

        resolved = config.get_plugin_config(
            plugin_type="reporter", plugin_name="default-on-offhost"
        )
        assert resolved["enabled"] is True, resolved
        assert FILE_ENDPOINT not in repr(resolved), resolved
        assert _built_from(config, _DefaultOnOffHostReporter) == {"enabled": True}


# ---------------------------------------------------------------------------
# An operator view the rule cannot be applied to
# ---------------------------------------------------------------------------


class _OpaqueView:
    """An operator view with no ``reporters`` the rule can reach.

    ``resolve_config`` records an AshConfig, whose ``reporters`` the rule edits. This
    stands for any other object recorded as the view: it answers
    ``get_plugin_config`` with what the file wrote and offers nothing to confine.
    """

    reporters = None

    def __init__(self, sections: Dict[str, Any]) -> None:
        self._sections = sections

    def get_plugin_config(self, plugin_type: str, plugin_name: str) -> Any:
        return copy.deepcopy(self._sections.get(plugin_name))


class TestAViewThatIsNotAnAshConfigIsRefused:
    """``_operator_reporters`` is an AshConfig, or None for a config that is the operator's own.

    ``record_operator_reporters`` records an AshConfig, and ``None`` means "no
    view". An object of another kind is a programming error: the command's step
    refuses it by name, and leaves the attribute and the scanner views recorded
    beside it as they were. It is not turned into ``None``, which would give that
    value a second meaning ("trusted") while the views recorded with it stay set.
    """

    def test_the_commands_step_refuses_it_and_records_nothing(self):
        section = S3_VIEWS["both-destinations"]
        config = _config({"s3": dict(section)})
        view = _OpaqueView({"s3": dict(section)})
        config._operator_reporters = view
        config._operator_scanner_views = [view]

        with pytest.raises(TypeError, match="operator view"):
            confine_off_host_reporters_to_overrides(
                config, [CONFIG_FILE], [], REPORT_CONFIG_FILE
            )

        assert config._operator_reporters is view
        assert config._operator_scanner_views == [view]

    def test_the_declared_reporters_step_refuses_it_too(self):
        """The second place the view is read: ``_confine`` for a command's config."""
        section = S3_VIEWS["both-destinations"]
        config = _config({"s3": dict(section)})
        config._operator_reporters = _OpaqueView({"s3": dict(section)})
        config._trusted_reporter_base = AshConfig()
        config._in_tree_config_files = (CONFIG_FILE,)
        config._reporters_from_overrides = True

        with pytest.raises(TypeError, match="operator view"):
            confine_declared_reporter_destinations(
                config, [S3Reporter], source=REPORT_CONFIG_FILE
            )

    def test_a_scan_does_not_read_the_view_in_these_steps(self):
        """Control: only a command that takes the settings from the overrides reads it."""
        section = S3_VIEWS["both-destinations"]
        config = _config({"s3": dict(section)})
        view = _OpaqueView({"s3": dict(section)})
        config._operator_reporters = view
        config._trusted_reporter_base = AshConfig()
        config._in_tree_config_files = (CONFIG_FILE,)

        confine_declared_reporter_destinations(
            config, [S3Reporter], source=REPORT_CONFIG_FILE
        )

        assert config._operator_reporters is view

    def test_no_view_is_not_refused(self):
        """Control: ``None`` is the config being the operator's own, and stays so."""
        section = S3_VIEWS["both-destinations"]
        config = _config({"s3": dict(section)}, view=None)

        _as_ash_report_confines(config, [S3Reporter])

        assert config._operator_reporters is None
        assert FILE_BUCKET not in repr(_built_from(config, S3Reporter))

    def test_a_view_that_can_be_confined_is_kept(self):
        """Control: an AshConfig view is confined on a copy and stays the view."""
        section = S3_VIEWS["both-destinations"]
        config = _config({"s3": dict(section)}, view={"s3": dict(section)})

        _as_ash_report_confines(config, [S3Reporter])

        assert isinstance(config._operator_reporters, AshConfig)
        assert FILE_BUCKET not in repr(
            config._operator_reporters.get_plugin_config(
                plugin_type="reporter", plugin_name="s3"
            )
        )
