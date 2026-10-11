# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash merge`` holds the config each shard recorded to the rules for a repository's config.

Each shard's ``ash_aggregated_results.json`` carries the config its scan resolved,
and ``ash merge`` builds its reporters from the lowest-indexed shard's copy. Which
of ASH's off-host plugin packages are loaded, where the reporters send findings
and which credentials send them are the operator's choice at merge time, as they
are for a config file inside the scanned tree during a scan
(``config/plugin_module_trust.py``, ``config/reporter_trust.py``): the defaults,
``--config`` outside the tree, and ``--config-overrides``.

Shards are written by ``AshAggregatedResults.save_model``, the scan's own writer,
and carry the config ``resolve_config`` returns for a config file outside any
tree, so the recorded config is one a real shard writes. No AWS call is made: the
AWS reporters' modules get a stand-in ``boto3``, their dependency checks report
unsatisfied unless a test says otherwise, and the S3 upload is recorded instead of
sent. Every reporter ``ReportPhase`` builds is kept, so a test can read what it
was built with whether or not it ran.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, ClassVar, Dict, List, Literal, Optional, Sequence, Tuple
from unittest.mock import MagicMock

import pytest
import yaml
from typer.testing import CliRunner

from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.cli.merge import RESULTS_FILE_NAME
from automated_security_helper.config.resolve_config import resolve_config
from tests.unit.cli.test_merge import (
    _make_shard_contribute_nothing,
    build_shards,
)

AWS = "automated_security_helper.plugin_modules.ash_aws_plugins"

#: A shard's config that loads the AWS reporters and points each at its own
#: destination.
SHARD_CONFIG: Dict[str, Any] = {
    "project_name": "test-merge",
    "ash_plugin_modules": [AWS],
    "reporters": {
        "s3": {
            "enabled": True,
            "options": {
                "aws_region": "us-west-2",
                "bucket_name": "shard-bucket",
                "key_prefix": "shard-prefix/",
            },
        },
        "aws-security-hub": {
            "enabled": True,
            "options": {"aws_region": "eu-west-1", "account_id": "123456789012"},
        },
        "bedrock-summary-reporter": {
            "enabled": True,
            "options": {"aws_region": "ap-southeast-2", "model_id": "shard-model"},
        },
    },
}

#: Every destination value ``SHARD_CONFIG`` sets.
SHARD_VALUES = (
    "us-west-2",
    "shard-bucket",
    "shard-prefix/",
    "eu-west-1",
    "123456789012",
    "ap-southeast-2",
    "shard-model",
)

#: The options ``SHARD_CONFIG`` sets that ``reporter_trust`` confines.
SHARD_DESTINATION_KEYS = (
    "reporters.s3.options.aws_region",
    "reporters.s3.options.bucket_name",
    "reporters.s3.options.key_prefix",
    "reporters.aws-security-hub.options.aws_region",
    "reporters.aws-security-hub.options.account_id",
    "reporters.bedrock-summary-reporter.options.aws_region",
    "reporters.bedrock-summary-reporter.options.model_id",
)

_RECORDED_KEY = re.compile(
    r"reporters\.[\w-]+\.(?:options\.\w+|enabled)|ash_plugin_modules"
)

ENDPOINT_DEFAULT = "https://default.invalid/"


class _EndpointOptions(ReporterOptionsBase):
    endpoint: str = ENDPOINT_DEFAULT


class _EndpointConfig(ReporterPluginConfigBase):
    name: Literal["endpoint-reporter"] = "endpoint-reporter"
    extension: str = "endpoint.json"
    enabled: bool = True
    options: _EndpointOptions = _EndpointOptions()


class _EndpointReporter(ReporterPluginBase[_EndpointConfig]):
    """A reporter a plugin module would add, with one declared destination option.

    Not decorated with ``@ash_reporter_plugin``, so it is never registered for the
    rest of the process; the harness hands it to the merge directly.
    """

    destination_options: ClassVar[Tuple[str, ...]] = ("endpoint",)

    def model_post_init(self, context):
        if self.config is None:
            self.config = _EndpointConfig()
        return super().model_post_init(context)

    def report(self, model):
        return json.dumps({"endpoint": self.config.options.endpoint})


def _write_yaml(path: Path, document: Dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return path


def _section(config: Any) -> Dict[str, Any]:
    """A reporter section or reporter config as a plain dict."""
    if config is None:
        return {}
    if hasattr(config, "model_dump"):
        return config.model_dump(by_alias=True)
    return dict(config)


class _Harness:
    """Runs ``ash merge`` through the CLI with the AWS reporters held offline."""

    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        import automated_security_helper.cli.merge as merge_module
        from automated_security_helper.core.phases.report_phase import ReportPhase
        from automated_security_helper.plugin_modules.ash_aws_plugins import (
            bedrock_summary_reporter,
            s3_reporter,
            security_hub_reporter,
        )
        from automated_security_helper.plugin_modules.ash_builtin.reporters.sarif_reporter import (
            SarifReporter,
        )
        from automated_security_helper.utils.log import ASH_LOGGER

        self.tmp_path = tmp_path
        self.monkeypatch = monkeypatch
        self.output_dir = tmp_path / "merged"
        self.built: List[Any] = []
        self.loaded_modules: List[List[str]] = []
        self.uploads: List[Dict[str, Any]] = []
        self.warnings: List[str] = []
        self.report_config: Optional[Any] = None
        self.boto3 = MagicMock()
        self.S3Reporter = s3_reporter.S3Reporter
        self.SecurityHubReporter = security_hub_reporter.SecurityHubReporter
        self.BedrockSummaryReporter = bedrock_summary_reporter.BedrockSummaryReporter
        self.reporters: List[type] = [
            SarifReporter,
            self.S3Reporter,
            self.SecurityHubReporter,
            self.BedrockSummaryReporter,
        ]

        for module in (s3_reporter, security_hub_reporter, bedrock_summary_reporter):
            monkeypatch.setattr(module, "boto3", self.boto3)
        for cls in self.reporters[1:]:
            monkeypatch.setattr(cls, "validate_plugin_dependencies", lambda _: False)
        monkeypatch.setattr(
            self.S3Reporter,
            "_put_object_with_retry",
            lambda _reporter, _client, **kwargs: self.uploads.append(kwargs),
        )

        original_filter = ReportPhase.filter_enabled_plugins

        def keep_built(phase, plugin_instances, plugin_context, python_only=False):
            self.built.extend(plugin_instances)
            self.report_config = phase.plugin_context.config
            return original_filter(phase, plugin_instances, plugin_context, python_only)

        monkeypatch.setattr(ReportPhase, "filter_enabled_plugins", keep_built)

        manager = MagicMock()
        manager.plugin_modules.side_effect = lambda plugin_type=None, **_: (
            list(self.reporters) if plugin_type == "reporter" else []
        )
        monkeypatch.setattr(merge_module, "ash_plugin_manager", manager)
        monkeypatch.setattr(
            merge_module,
            "load_plugins",
            lambda plugin_context=None: self.loaded_modules.append(
                list(plugin_context.config.ash_plugin_modules)
            ),
        )
        monkeypatch.setattr(
            ASH_LOGGER,
            "warning",
            lambda message, *args, **kwargs: self.warnings.append(str(message)),
        )

    def satisfy(self, reporter_class: type) -> None:
        """Let ``reporter_class``'s dependency check pass, so it runs."""
        self.monkeypatch.setattr(
            reporter_class, "validate_plugin_dependencies", lambda _: True
        )

    def recorded_config(self, document: Dict[str, Any]):
        """The config a shard records for ``document``: what its scan resolved."""
        return resolve_config(
            config_path=_write_yaml(
                self.tmp_path / "shard-config" / "ash.yaml", document
            )
        )

    def write_shards(self, document: Dict[str, Any], shard_count: int = 2):
        """Each shard's results file, written by the scan's writer, recording ``document``."""
        return self.write_models(build_shards(shard_count), document)

    def write_models(self, models: Sequence[Any], document: Dict[str, Any]):
        recorded = self.recorded_config(document)
        paths = []
        for index, model in enumerate(models):
            model.ash_config = recorded
            target = self.tmp_path / "artifacts" / f"shard-{index}"
            model.save_model(target)
            paths.append(target / RESULTS_FILE_NAME)
        return paths

    def merge(self, shard_paths: Sequence[Path], *args: str):
        from automated_security_helper.cli.main import app

        argv = ["merge"]
        for path in shard_paths:
            argv += ["--results", str(path)]
        argv += ["--output-dir", str(self.output_dir), *args]
        return CliRunner().invoke(app, argv)

    def instance(self, reporter_class: type):
        found = [item for item in self.built if isinstance(item, reporter_class)]
        assert len(found) == 1, f"{reporter_class.__name__} built {len(found)} times"
        return found[0]

    def options(self, reporter_class: type) -> Dict[str, Any]:
        return _section(self.instance(reporter_class).config).get("options") or {}

    def ignoring(self) -> List[str]:
        return [message for message in self.warnings if message.startswith("Ignoring")]

    def ignored_keys(self, messages: Optional[Sequence[str]] = None) -> set:
        return {
            key
            for message in (self.ignoring() if messages is None else messages)
            for key in _RECORDED_KEY.findall(message)
        }

    def aws_calls(self) -> str:
        return repr(self.boto3.mock_calls)


@pytest.fixture
def harness(tmp_path, monkeypatch):
    for name in (
        "ASH_CONFIG",
        "ASH_S3_BUCKET_NAME",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
        "AWS_PROFILE",
        "ASH_BEDROCK_MODEL_ID",
    ):
        monkeypatch.delenv(name, raising=False)
    # The collector job's working directory, outside any checkout, so the config
    # files the tests write elsewhere under tmp_path are outside its tree.
    collector = tmp_path / "collector"
    collector.mkdir()
    monkeypatch.chdir(collector)
    return _Harness(tmp_path, monkeypatch)


def _assert_merged(result, harness: _Harness) -> None:
    """The merge ran to its verdict: exit 2 for the fixtures' findings, results written."""
    assert result.exit_code == 2, (result.output, result.exception)
    assert (harness.output_dir / RESULTS_FILE_NAME).is_file(), result.output


class TestRecordedReporterDestinations:
    def test_a_shards_s3_bucket_is_not_used_and_the_warning_names_it(self, harness):
        """The operator's base is the defaults: S3 gets no bucket, and nothing uploads."""
        shard_paths = harness.write_shards(SHARD_CONFIG)

        result = harness.merge(shard_paths)

        _assert_merged(result, harness)
        options = harness.options(harness.S3Reporter)
        assert options.get("bucket_name") is None
        assert options.get("aws_region") is None
        assert options.get("key_prefix") == "ash-reports/"
        assert harness.uploads == []
        assert not (harness.output_dir / "reports" / "ash.s3.json").exists()
        ignored = harness.ignored_keys()
        for key in (
            "reporters.s3.options.aws_region",
            "reporters.s3.options.bucket_name",
            "reporters.s3.options.key_prefix",
        ):
            assert key in ignored, harness.warnings
        named = [m for m in harness.ignoring() if "reporters.s3." in m]
        assert any(shard_paths[0].as_posix() in message for message in named)
        for value in SHARD_VALUES:
            assert value not in harness.aws_calls()

    def test_an_operator_config_with_s3_off_and_no_bucket(self, harness):
        """The brief's case: the operator loads the AWS reporters, S3 off, no bucket."""
        shard_paths = harness.write_shards(SHARD_CONFIG)
        operator = _write_yaml(
            harness.tmp_path / "operator" / "ash.yaml",
            {"ash_plugin_modules": [AWS], "reporters": {"s3": {"enabled": False}}},
        )

        result = harness.merge(shard_paths, "--config", str(operator))

        _assert_merged(result, harness)
        assert harness.options(harness.S3Reporter).get("bucket_name") is None
        assert harness.uploads == []
        assert not (harness.output_dir / "reports" / "ash.s3.json").exists()
        assert "reporters.s3.options.bucket_name" in harness.ignored_keys()
        assert "shard-bucket" not in harness.aws_calls()
        # The operator's config loads the package, so the shard's entry is kept.
        assert harness.loaded_modules == [[AWS]]

    def test_an_operator_override_sets_where_s3_sends(self, harness):
        """``--config-overrides`` win: the upload goes to the operator's bucket."""
        harness.satisfy(harness.S3Reporter)
        shard_paths = harness.write_shards(SHARD_CONFIG)

        result = harness.merge(
            shard_paths,
            "--config-overrides",
            f"ash_plugin_modules=[{AWS}]",
            "--config-overrides",
            "reporters.s3.enabled=true",
            "--config-overrides",
            "reporters.s3.options.bucket_name=operator-bucket",
            "--config-overrides",
            "reporters.s3.options.aws_region=us-east-2",
        )

        _assert_merged(result, harness)
        assert len(harness.uploads) == 1, harness.uploads
        upload = harness.uploads[0]
        assert upload["Bucket"] == "operator-bucket"
        # The shard's key prefix is not the operator's, so the default applies.
        assert upload["Key"].startswith("ash-reports/")
        receipt = json.loads(
            (harness.output_dir / "reports" / "ash.s3.json").read_text("utf-8")
        )
        assert receipt["bucket"] == "operator-bucket"
        ignored = harness.ignored_keys()
        assert "reporters.s3.options.key_prefix" in ignored
        assert "reporters.s3.options.bucket_name" not in ignored
        assert "reporters.s3.options.aws_region" not in ignored

    def test_security_hub_and_bedrock_destinations_are_confined(self, harness):
        shard_paths = harness.write_shards(SHARD_CONFIG)
        operator = _write_yaml(
            harness.tmp_path / "operator" / "ash.yaml",
            {"ash_plugin_modules": [AWS]},
        )

        result = harness.merge(shard_paths, "--config", str(operator))

        _assert_merged(result, harness)
        hub = harness.options(harness.SecurityHubReporter)
        assert hub.get("aws_region") != "eu-west-1"
        assert hub.get("account_id") is None
        bedrock = harness.options(harness.BedrockSummaryReporter)
        assert bedrock.get("aws_region") != "ap-southeast-2"
        assert bedrock.get("model_id") != "shard-model"
        ignored = harness.ignored_keys()
        for key in (
            "reporters.aws-security-hub.options.aws_region",
            "reporters.aws-security-hub.options.account_id",
            "reporters.bedrock-summary-reporter.options.aws_region",
            "reporters.bedrock-summary-reporter.options.model_id",
        ):
            assert key in ignored, harness.warnings
        for value in SHARD_VALUES:
            assert value not in harness.aws_calls()

    def test_a_plugin_reporters_declared_destination_is_confined(self, harness):
        harness.reporters.append(_EndpointReporter)
        shard_paths = harness.write_shards(
            {
                "reporters": {
                    "endpoint-reporter": {
                        "options": {"endpoint": "https://shard.invalid/"}
                    }
                }
            }
        )

        result = harness.merge(shard_paths)

        _assert_merged(result, harness)
        written = json.loads(
            (harness.output_dir / "reports" / "ash.endpoint.json").read_text("utf-8")
        )
        assert written == {"endpoint": ENDPOINT_DEFAULT}
        assert "reporters.endpoint-reporter.options.endpoint" in harness.ignored_keys()

    def test_the_merged_results_do_not_record_the_shards_destinations(self, harness):
        shard_paths = harness.write_shards(SHARD_CONFIG)

        result = harness.merge(shard_paths)

        _assert_merged(result, harness)
        merged = (harness.output_dir / RESULTS_FILE_NAME).read_text("utf-8")
        for value in SHARD_VALUES:
            assert value not in merged
        recorded = json.loads(merged)["ash_config"]
        assert AWS not in recorded["ash_plugin_modules"]


class TestRecordedPluginModules:
    def test_a_shards_off_host_plugin_package_is_not_loaded(self, harness):
        shard_paths = harness.write_shards(SHARD_CONFIG)

        result = harness.merge(shard_paths)

        _assert_merged(result, harness)
        assert harness.loaded_modules == [[]]
        named = [m for m in harness.ignoring() if "ash_plugin_modules" in m]
        assert named and AWS in named[0], harness.warnings
        assert shard_paths[0].as_posix() in named[0]

    def test_an_override_loads_the_package(self, harness):
        shard_paths = harness.write_shards(SHARD_CONFIG)

        result = harness.merge(
            shard_paths, "--config-overrides", f"ash_plugin_modules=[{AWS}]"
        )

        _assert_merged(result, harness)
        assert harness.loaded_modules == [[AWS]]
        assert not [m for m in harness.ignoring() if "ash_plugin_modules" in m]


class TestTheOperatorsBase:
    def test_a_recorded_config_repeating_the_operators_values_merges_without_a_warning(
        self, harness
    ):
        """Positive control: the operator's own values are kept, with no warning."""
        shard_paths = harness.write_shards(SHARD_CONFIG)
        operator = _write_yaml(harness.tmp_path / "operator" / "ash.yaml", SHARD_CONFIG)

        result = harness.merge(shard_paths, "--config", str(operator))

        _assert_merged(result, harness)
        assert harness.ignoring() == []
        assert harness.loaded_modules == [[AWS]]
        s3 = harness.options(harness.S3Reporter)
        assert s3["bucket_name"] == "shard-bucket"
        assert s3["key_prefix"] == "shard-prefix/"
        assert harness.options(harness.SecurityHubReporter)["account_id"] == (
            "123456789012"
        )
        assert harness.options(harness.BedrockSummaryReporter)["model_id"] == (
            "shard-model"
        )

    def test_a_merge_with_no_off_host_settings_warns_about_nothing(self, harness):
        """Control: a recorded config that sets no confined option changes nothing."""
        shard_paths = harness.write_shards({"project_name": "test-merge"})

        result = harness.merge(shard_paths)

        _assert_merged(result, harness)
        assert harness.ignoring() == []
        assert harness.loaded_modules == [[]]

    def test_a_config_inside_the_collectors_checkout_is_not_the_operators(
        self, harness
    ):
        """``--config`` inside the working directory's checkout is a repository's file.

        As for ``ash report``: the trusted base is the defaults, so neither that
        file's bucket nor the shard's is used.
        """
        collector = Path.cwd()
        (collector / ".git").mkdir()
        in_checkout = _write_yaml(
            collector / "ash.yaml",
            {
                "ash_plugin_modules": [AWS],
                "reporters": {
                    "s3": {
                        "enabled": True,
                        "options": {
                            "aws_region": "us-east-2",
                            "bucket_name": "checkout-bucket",
                        },
                    }
                },
            },
        )
        shard_paths = harness.write_shards(SHARD_CONFIG)

        result = harness.merge(shard_paths, "--config", str(in_checkout))

        _assert_merged(result, harness)
        assert harness.options(harness.S3Reporter).get("bucket_name") is None
        assert harness.loaded_modules == [[]]
        assert "reporters.s3.options.bucket_name" in harness.ignored_keys()

    def test_the_same_rules_as_a_config_file_inside_the_scanned_tree(self, harness):
        """What merge keeps of a recorded config is what a scan keeps of an in-tree file.

        Compared against ``resolve_config`` for a scan whose ``.ash/.ash.yaml``
        holds the same document and whose operator config is the one passed to
        ``ash merge``, so a rule added to the shared tables applies to both.
        """
        operator_document = {
            "ash_plugin_modules": [AWS],
            "reporters": {
                "s3": {"enabled": False, "options": {"bucket_name": "operator-bucket"}},
                "aws-security-hub": {"options": {"aws_region": "us-east-2"}},
            },
        }
        operator = _write_yaml(
            harness.tmp_path / "operator" / "ash.yaml", operator_document
        )
        repo = harness.tmp_path / "repo"
        (repo / ".git").mkdir(parents=True)
        _write_yaml(repo / ".ash" / ".ash.yaml", SHARD_CONFIG)
        scanned = resolve_config(source_dir=repo, trusted_config_path=operator)
        scan_ignored = harness.ignored_keys()
        harness.warnings.clear()
        shard_paths = harness.write_shards(SHARD_CONFIG)

        result = harness.merge(shard_paths, "--config", str(operator))

        _assert_merged(result, harness)
        merged = harness.report_config
        assert merged is not None
        for name in ("s3", "aws-security-hub", "bedrock-summary-reporter"):
            assert _section(merged.get_plugin_config("reporter", name)) == _section(
                scanned.get_plugin_config("reporter", name)
            ), name
        assert list(merged.ash_plugin_modules) == list(scanned.ash_plugin_modules)
        assert harness.ignored_keys() == scan_ignored
        assert set(SHARD_DESTINATION_KEYS) <= scan_ignored


class TestOverridesApplyOverTheRecordedConfig:
    def test_an_override_reaches_the_pre_merge_completion_gate(self, harness):
        """The recorded config's ``fail_on_incomplete_scanners`` is the operator's to change.

        One shard completed nothing, which the gate refuses by default; the
        override turns the gate off the same way ``--no-fail-on-incomplete-scanners``
        does, so the merge runs and exits 2 for the other shards' findings.
        """
        shards = build_shards(3)
        _make_shard_contribute_nothing(shards[1])
        shard_paths = harness.write_models(shards, {"project_name": "test-merge"})

        result = harness.merge(
            shard_paths, "--config-overrides", "fail_on_incomplete_scanners=false"
        )

        _assert_merged(result, harness)

    def test_an_invalid_override_exits_three(self, harness):
        shard_paths = harness.write_shards({"project_name": "test-merge"})

        result = harness.merge(shard_paths, "--config-overrides", "no-separator")

        assert result.exit_code == 3, (result.output, result.exception)
        assert "Invalid configuration" in result.output
        assert not (harness.output_dir / RESULTS_FILE_NAME).exists()
