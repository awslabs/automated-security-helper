# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash merge`` holds the config each shard recorded to the rules for a repository's config.

Each shard's ``ash_aggregated_results.json`` carries the config its scan resolved,
and ``ash merge`` builds its reporters from the lowest-indexed shard's copy. What a
config file inside the scanned tree may not choose is the operator's choice at
merge time (``resolve_config.confine_to_trusted_base``): which plugin modules are
imported, whether the off-host reporters run, where reporters send findings and
with which credentials, the sandbox grants and the scanners' own config files. The
operator's values are the defaults, ``--config`` outside the working directory's
tree, and ``--config-overrides``. The settings the verdict reads still come from
the shards, and shards that disagree on one are refused.

Shards are written by ``AshAggregatedResults.save_model``, the scan's own writer,
and carry the config ``resolve_config`` returns for a config file outside any
tree, so the recorded config is one a real shard writes. No AWS call is made: the
AWS reporters' modules get a stand-in ``boto3``, their dependency checks report
unsatisfied unless a test says otherwise, their ``report`` calls are recorded, and
the S3 upload is recorded instead of sent. Every reporter ``ReportPhase`` builds is
kept, so a test can read what it was built with whether or not it ran.
``TestTheRealChain`` runs the merge in a fresh process with nothing patched.
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
    r"|sandbox\.\w+|scanners\.[\w-]+\.options\.\w+"
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
            cloudwatch_logs_reporter,
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
        self.reported: List[str] = []
        self.warnings: List[str] = []
        self.report_config: Optional[Any] = None
        self.boto3 = MagicMock()
        self.S3Reporter = s3_reporter.S3Reporter
        self.SecurityHubReporter = security_hub_reporter.SecurityHubReporter
        self.BedrockSummaryReporter = bedrock_summary_reporter.BedrockSummaryReporter
        self.CloudWatchLogsReporter = cloudwatch_logs_reporter.CloudWatchLogsReporter
        self.aws_reporters: List[type] = [
            self.S3Reporter,
            self.SecurityHubReporter,
            self.BedrockSummaryReporter,
            self.CloudWatchLogsReporter,
        ]
        self.reporters: List[type] = [SarifReporter, *self.aws_reporters]

        for module in (
            s3_reporter,
            security_hub_reporter,
            bedrock_summary_reporter,
            cloudwatch_logs_reporter,
        ):
            monkeypatch.setattr(module, "boto3", self.boto3)
        for cls in self.aws_reporters:
            monkeypatch.setattr(cls, "validate_plugin_dependencies", lambda _: False)
            monkeypatch.setattr(cls, "report", self._recording(cls, cls.report))
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

    def _recording(self, reporter_class: type, report):
        def recorded(reporter, model):
            self.reported.append(reporter_class.__name__)
            return report(reporter, model)

        return recorded

    def satisfy(self, reporter_class: type) -> None:
        """Let ``reporter_class``'s dependency check pass, so it runs."""
        self.monkeypatch.setattr(
            reporter_class, "validate_plugin_dependencies", lambda _: True
        )

    def satisfy_s3_when_it_has_a_destination(self) -> None:
        """S3's dependency check passes once it has a bucket and a region.

        The real check needs both before it calls AWS. So the S3 reporter runs, and
        uploads, exactly when the config it was built from names a destination.
        """
        self.monkeypatch.setattr(
            self.S3Reporter,
            "validate_plugin_dependencies",
            lambda reporter: bool(
                reporter.config.options.bucket_name
                and reporter.config.options.aws_region
            ),
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

    def built_of(self, reporter_class: type) -> List[Any]:
        return [item for item in self.built if isinstance(item, reporter_class)]

    def instance(self, reporter_class: type):
        found = self.built_of(reporter_class)
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
    def test_a_shards_s3_destination_is_not_used_and_the_warning_names_it(
        self, harness
    ):
        """The operator loads the AWS reporters and sets no destination: S3 gets none."""
        harness.satisfy_s3_when_it_has_a_destination()
        shard_paths = harness.write_shards(SHARD_CONFIG)
        operator = _write_yaml(
            harness.tmp_path / "operator" / "ash.yaml", {"ash_plugin_modules": [AWS]}
        )

        result = harness.merge(shard_paths, "--config", str(operator))

        _assert_merged(result, harness)
        options = harness.options(harness.S3Reporter)
        assert options.get("bucket_name") is None
        assert options.get("aws_region") is None
        assert options.get("key_prefix") == "ash-reports/"
        assert "S3Reporter" not in harness.reported
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
        """The operator loads the AWS reporters, S3 off, no bucket: S3 does not run."""
        harness.satisfy(harness.S3Reporter)
        shard_paths = harness.write_shards(SHARD_CONFIG)
        operator = _write_yaml(
            harness.tmp_path / "operator" / "ash.yaml",
            {"ash_plugin_modules": [AWS], "reporters": {"s3": {"enabled": False}}},
        )

        result = harness.merge(shard_paths, "--config", str(operator))

        _assert_merged(result, harness)
        assert harness.options(harness.S3Reporter).get("bucket_name") is None
        assert _section(harness.instance(harness.S3Reporter).config)["enabled"] is False
        assert "S3Reporter" not in harness.reported
        assert harness.uploads == []
        assert not (harness.output_dir / "reports" / "ash.s3.json").exists()
        ignored = harness.ignored_keys()
        assert "reporters.s3.options.bucket_name" in ignored
        assert "reporters.s3.enabled" in ignored
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
        # The merged results are written after the plugin load too, so they record
        # the declared destination as confined.
        merged = (harness.output_dir / RESULTS_FILE_NAME).read_text("utf-8")
        assert "https://shard.invalid/" not in merged
        named = [m for m in harness.ignoring() if "endpoint-reporter" in m]
        assert named, harness.warnings
        assert "reporters.endpoint-reporter.options.endpoint" in harness.ignored_keys(
            named
        )
        assert "ash merge's --config-overrides or --config" in named[0]

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
        message = named[0]
        assert shard_paths[0].as_posix() in message
        assert "only modules the operator's configuration names are imported" in message
        assert "installed modules outside the tree" not in message

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

    @pytest.mark.parametrize("checkout", [True, False], ids=["checkout", "plain-dir"])
    def test_a_config_inside_the_working_directorys_tree_is_not_the_operators(
        self, harness, checkout
    ):
        """``--config`` inside the working directory's tree is a repository's file.

        As for ``ash report``. The tree is the outermost git checkout around the
        working directory, or the working directory itself when it is in none, so
        a file there is not the operator's either way. The trusted base is then
        the defaults: the AWS reporters' package is not loaded, and neither that
        file's bucket nor the shard's reaches an S3 reporter built in this process.
        """
        harness.satisfy_s3_when_it_has_a_destination()
        collector = Path.cwd()
        if checkout:
            (collector / ".git").mkdir()
        assert (collector / ".git").exists() is checkout
        in_tree = _write_yaml(
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

        result = harness.merge(shard_paths, "--config", str(in_tree))

        _assert_merged(result, harness)
        assert harness.loaded_modules == [[]]
        # The harness hands the merge the S3 reporter whatever is loaded.
        for built in harness.built_of(harness.S3Reporter):
            assert _section(built.config)["options"].get("bucket_name") is None
        assert "S3Reporter" not in harness.reported
        assert harness.uploads == []
        assert "reporters.s3.options.bucket_name" in harness.ignored_keys()

    def test_the_same_rules_as_a_config_file_inside_the_scanned_tree(self, harness):
        """What merge keeps of a recorded config is what a scan keeps of an in-tree file.

        Compared against ``resolve_config`` for a scan whose ``.ash/.ash.yaml``
        holds the same document and whose operator config is the one passed to
        ``ash merge``, so a rule added to the shared tables applies to both. The
        document stays inside what both treat alike: the merge is stricter about a
        module the operator does not name, which ``TestRecordedThirdPartyModules``
        pins. ``enabled`` comes from the operator in both directions in both, and
        ``TestEnablementIsTheOperators`` pins the merge's side of it.
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

    def test_an_operators_sandbox_override_is_kept(self, harness):
        """A ``sandbox`` override is the operator's grant, not a shard's.

        It is applied to each shard's recorded config and replayed onto the
        trusted base, so the sandbox step finds it in both and keeps it.
        """
        grant = harness.tmp_path / "operator-grant"
        grant.mkdir()
        shard_paths = harness.write_shards({"project_name": "test-merge"})

        result = harness.merge(
            shard_paths,
            "--config-overrides",
            f"sandbox.extra_read_paths={json.dumps([grant.as_posix()])}",
        )

        _assert_merged(result, harness)
        assert not [m for m in harness.ignoring() if "sandbox." in m], harness.warnings
        recorded = json.loads(
            (harness.output_dir / RESULTS_FILE_NAME).read_text("utf-8")
        )["ash_config"]
        assert recorded["sandbox"]["extra_read_paths"] == [grant.as_posix()]

    def test_an_invalid_override_exits_three(self, harness):
        shard_paths = harness.write_shards({"project_name": "test-merge"})

        result = harness.merge(shard_paths, "--config-overrides", "no-separator")

        assert result.exit_code == 3, (result.output, result.exception)
        assert "Invalid configuration" in result.output
        assert not (harness.output_dir / RESULTS_FILE_NAME).exists()


def _write_each(harness: _Harness, models, documents) -> List[Path]:
    """Shards that each record their own document, written by the scan's writer."""
    paths = []
    for index, (model, document) in enumerate(zip(models, documents)):
        model.ash_config = harness.recorded_config(document)
        target = harness.tmp_path / "artifacts" / f"shard-{index}"
        model.save_model(target)
        paths.append(target / RESULTS_FILE_NAME)
    return paths


class TestEnablementIsTheOperators:
    def test_a_shard_does_not_turn_on_s3_the_operators_config_turns_off(self, harness):
        """The operator's config names a bucket and turns S3 off; a shard turns it on."""
        harness.satisfy(harness.S3Reporter)
        shard_paths = harness.write_shards(SHARD_CONFIG)
        operator = _write_yaml(
            harness.tmp_path / "operator" / "ash.yaml",
            {
                "ash_plugin_modules": [AWS],
                "reporters": {
                    "s3": {
                        "enabled": False,
                        "options": {
                            "bucket_name": "operator-bucket",
                            "aws_region": "us-east-2",
                        },
                    }
                },
            },
        )

        result = harness.merge(shard_paths, "--config", str(operator))

        _assert_merged(result, harness)
        assert "S3Reporter" not in harness.reported
        assert harness.uploads == []
        assert _section(harness.instance(harness.S3Reporter).config)["enabled"] is False
        assert "reporters.s3.enabled" in harness.ignored_keys()

    def test_a_shard_does_not_turn_on_bedrock_the_operators_config_turns_off(
        self, harness
    ):
        harness.satisfy(harness.BedrockSummaryReporter)
        shard_paths = harness.write_shards(SHARD_CONFIG)
        operator = _write_yaml(
            harness.tmp_path / "operator" / "ash.yaml",
            {
                "ash_plugin_modules": [AWS],
                "reporters": {
                    "s3": {"enabled": False},
                    "aws-security-hub": {"enabled": False},
                    "bedrock-summary-reporter": {"enabled": False},
                },
            },
        )

        result = harness.merge(shard_paths, "--config", str(operator))

        _assert_merged(result, harness)
        assert "BedrockSummaryReporter" not in harness.reported
        assert "converse" not in harness.aws_calls()
        assert "reporters.bedrock-summary-reporter.enabled" in harness.ignored_keys()

    def test_a_shard_that_loads_the_aws_reporters_and_names_a_bucket_uploads_nothing(
        self, harness
    ):
        """No operator setting at all: the shard's package and bucket are both refused."""
        harness.satisfy_s3_when_it_has_a_destination()
        shard_paths = harness.write_shards(SHARD_CONFIG)

        result = harness.merge(shard_paths)

        _assert_merged(result, harness)
        assert harness.loaded_modules == [[]]
        assert "S3Reporter" not in harness.reported
        assert harness.uploads == []
        ignored = harness.ignored_keys()
        assert "ash_plugin_modules" in ignored
        assert "reporters.s3.options.bucket_name" in ignored

    def test_a_shard_does_not_turn_off_s3_the_operators_config_turns_on(self, harness):
        """The operator enables S3 with its bucket; a shard records it off. It runs."""
        harness.satisfy(harness.S3Reporter)
        shard_paths = harness.write_shards(
            {"ash_plugin_modules": [AWS], "reporters": {"s3": {"enabled": False}}}
        )
        operator = _write_yaml(
            harness.tmp_path / "operator" / "ash.yaml",
            {
                "ash_plugin_modules": [AWS],
                "reporters": {
                    "s3": {
                        "enabled": True,
                        "options": {
                            "bucket_name": "operator-bucket",
                            "aws_region": "us-east-2",
                        },
                    }
                },
            },
        )

        result = harness.merge(shard_paths, "--config", str(operator))

        _assert_merged(result, harness)
        assert "S3Reporter" in harness.reported
        assert [upload["Bucket"] for upload in harness.uploads] == ["operator-bucket"]
        named = [m for m in harness.ignoring() if "reporters.s3.enabled" in m]
        assert named, harness.warnings
        assert "ash merge's --config-overrides or --config" in named[0]

    def test_a_shard_does_not_turn_off_a_reporter_the_operator_leaves_on_by_default(
        self, harness
    ):
        """The operator's config is silent, so the reporter's default (on) applies."""
        harness.satisfy(harness.SecurityHubReporter)
        shard_paths = harness.write_shards(
            {
                "ash_plugin_modules": [AWS],
                "reporters": {"aws-security-hub": {"enabled": False}},
            }
        )
        operator = _write_yaml(
            harness.tmp_path / "operator" / "ash.yaml", {"ash_plugin_modules": [AWS]}
        )

        result = harness.merge(shard_paths, "--config", str(operator))

        _assert_merged(result, harness)
        built = _section(harness.instance(harness.SecurityHubReporter).config)
        assert built["enabled"] is True
        assert "SecurityHubReporter" in harness.reported
        assert "reporters.aws-security-hub.enabled" in harness.ignored_keys()

    def test_a_shard_does_not_turn_off_a_plugin_reporter_with_destinations(
        self, harness
    ):
        """The rule covers a reporter a plugin module adds that declares destinations."""
        harness.reporters.append(_EndpointReporter)
        shard_paths = harness.write_shards(
            {"reporters": {"endpoint-reporter": {"enabled": False}}}
        )

        result = harness.merge(shard_paths)

        _assert_merged(result, harness)
        written = json.loads(
            (harness.output_dir / "reports" / "ash.endpoint.json").read_text("utf-8")
        )
        assert written == {"endpoint": ENDPOINT_DEFAULT}
        named = [m for m in harness.ignoring() if "endpoint-reporter.enabled" in m]
        assert named, harness.warnings
        assert "ash merge's --config-overrides or --config" in named[0]

    def test_a_shard_that_repeats_the_operators_enabled_is_not_warned_about(
        self, harness
    ):
        """Control: the operator and the shard both turn S3 off, so nothing differs."""
        shard_paths = harness.write_shards(
            {"ash_plugin_modules": [AWS], "reporters": {"s3": {"enabled": False}}}
        )
        operator = _write_yaml(
            harness.tmp_path / "operator" / "ash.yaml",
            {"ash_plugin_modules": [AWS], "reporters": {"s3": {"enabled": False}}},
        )

        result = harness.merge(shard_paths, "--config", str(operator))

        _assert_merged(result, harness)
        assert _section(harness.instance(harness.S3Reporter).config)["enabled"] is False
        assert "reporters.s3.enabled" not in harness.ignored_keys()


def _documented_s3_example_overrides() -> List[str]:
    """The ``--config-overrides`` values of the S3 example in the ash merge docs."""
    import shlex

    from tests.utils.helpers import REPO_ROOT

    text = (REPO_ROOT / "docs" / "content" / "docs" / "cli-reference.md").read_text(
        encoding="utf-8"
    )
    section = text.split(
        "#### Settings a shard's recorded configuration cannot choose", 1
    )[1]
    block = section.split("```bash\n", 1)[1].split("```", 1)[0]
    words = shlex.split(block.replace("\\\n", " "))
    assert words[:2] == ["ash", "merge"], words
    return [
        words[i + 1] for i, word in enumerate(words) if word == "--config-overrides"
    ]


class TestTheDocumentedS3Example:
    def test_the_example_uploads_to_s3_and_runs_no_other_aws_reporter(self, harness):
        for reporter_class in harness.aws_reporters:
            harness.satisfy(reporter_class)
        overrides = _documented_s3_example_overrides()
        assert overrides, "the docs no longer hold the S3 example"
        shard_paths = harness.write_shards({"project_name": "test-merge"})
        args: List[str] = []
        for value in overrides:
            args += ["--config-overrides", value]

        result = harness.merge(shard_paths, *args)

        _assert_merged(result, harness)
        assert harness.reported == ["S3Reporter"]
        assert [upload["Bucket"] for upload in harness.uploads] == ["my-bucket"]
        assert harness.loaded_modules == [[AWS]]


class TestMergeWarnings:
    def test_the_warnings_name_the_results_file_and_ash_merges_options(self, harness):
        shard_paths = harness.write_shards(SHARD_CONFIG)

        result = harness.merge(shard_paths)

        _assert_merged(result, harness)
        messages = harness.ignoring()
        assert {"ash_plugin_modules", "reporters.s3.options.bucket_name"} <= (
            harness.ignored_keys()
        )
        for message in messages:
            assert shard_paths[0].as_posix() in message, message
            assert "a shard recorded in its results" in message, message
            assert "ash merge's --config-overrides or --config" in message, message
            assert "inside the scanned tree" not in message, message
            assert "--ash-plugin-modules" not in message, message

    def test_every_confinement_step_runs_on_the_recorded_config(self, harness):
        """Sandbox grants and scanner config files are confined too, not only reporters.

        Their warnings name the results file and say why a shard's value is not
        used, and give no remedy: no scanner runs during a merge, so the value
        would change only what the merged results record.
        """
        outside = harness.tmp_path / "elsewhere"
        outside.mkdir()
        bandit_config = outside / "bandit.yaml"
        bandit_config.write_text("skips: []\n", encoding="utf-8")
        shard_paths = harness.write_shards(
            {
                "sandbox": {"extra_read_paths": [str(outside)]},
                "scanners": {
                    "bandit": {"options": {"config_file": str(bandit_config)}}
                },
            }
        )

        result = harness.merge(shard_paths)

        _assert_merged(result, harness)
        ignored = harness.ignored_keys()
        assert "sandbox.extra_read_paths" in ignored, harness.warnings
        assert "scanners.bandit.options.config_file" in ignored, harness.warnings
        recorded = json.loads(
            (harness.output_dir / RESULTS_FILE_NAME).read_text("utf-8")
        )["ash_config"]
        assert recorded["sandbox"]["extra_read_paths"] == []
        assert str(bandit_config) not in json.dumps(recorded)
        messages = [
            m
            for m in harness.ignoring()
            if "sandbox.extra_read_paths" in m
            or "scanners.bandit.options.config_file" in m
        ]
        assert len(messages) == 2, harness.warnings
        for message in messages:
            assert shard_paths[0].as_posix() in message, message
            assert "a shard recorded in its results" in message, message
            assert "No scanner runs during a merge" in message, message
            assert "inside the scanned tree" not in message, message
            assert "Set these with" not in message, message
            assert "Set them with" not in message, message


class TestRecordedThirdPartyModules:
    MODULE = "merge_probe_ash_plugins"

    def _install(self, harness) -> None:
        """An installed plugin package outside every tree, on ``sys.path`` for the test."""
        site = harness.tmp_path / "site"
        package = site / self.MODULE
        package.mkdir(parents=True)
        (package / "__init__.py").write_text("ASH_REPORTERS = []\n", encoding="utf-8")
        harness.monkeypatch.syspath_prepend(str(site))

    def test_an_installed_module_the_operator_does_not_name_is_not_loaded(
        self, harness
    ):
        self._install(harness)
        shard_paths = harness.write_shards({"ash_plugin_modules": [self.MODULE]})

        result = harness.merge(shard_paths)

        _assert_merged(result, harness)
        assert harness.loaded_modules == [[]]
        named = [m for m in harness.ignoring() if self.MODULE in m]
        assert named and "the operator's configuration does not name it" in named[0]

    def test_a_module_the_operator_names_is_loaded(self, harness):
        """Control: the same entry, named by the operator too, is kept."""
        self._install(harness)
        shard_paths = harness.write_shards({"ash_plugin_modules": [self.MODULE]})
        operator = _write_yaml(
            harness.tmp_path / "operator" / "ash.yaml",
            {"ash_plugin_modules": [self.MODULE]},
        )

        result = harness.merge(shard_paths, "--config", str(operator))

        _assert_merged(result, harness)
        assert harness.loaded_modules == [[self.MODULE]]
        assert not [m for m in harness.ignoring() if self.MODULE in m]


class TestShardOrder:
    def test_the_lowest_indexed_shard_supplies_the_config_in_any_argument_order(
        self, harness
    ):
        """Shards given in reverse: the warnings still name shard 0's results file."""
        shard_paths = harness.write_shards(SHARD_CONFIG, shard_count=3)

        result = harness.merge(list(reversed(shard_paths)))

        _assert_merged(result, harness)
        messages = harness.ignoring()
        assert messages
        for message in messages:
            assert shard_paths[0].as_posix() in message, message
            assert shard_paths[2].as_posix() not in message, message

    def test_the_completion_gate_answers_the_same_in_any_argument_order(self, harness):
        shards = build_shards(3)
        _make_shard_contribute_nothing(shards[1])
        paths = _write_each(
            harness,
            shards,
            [{"fail_on_incomplete_scanners": value} for value in (True, True, False)],
        )

        in_order = harness.merge(paths)
        harness.output_dir = harness.tmp_path / "merged-reordered"
        reordered = harness.merge([paths[2], paths[0], paths[1]])

        assert in_order.exit_code == reordered.exit_code, (
            in_order.output,
            reordered.output,
        )


#: A setting the verdict reads, and two values for it.
VERDICT_DISAGREEMENTS = [
    ("fail_on_findings", {"fail_on_findings": False}, {"fail_on_findings": True}),
    (
        "fail_on_incomplete_scanners",
        {"fail_on_incomplete_scanners": False},
        {"fail_on_incomplete_scanners": True},
    ),
    (
        "global_settings.severity_threshold",
        {"global_settings": {"severity_threshold": "LOW"}},
        {"global_settings": {"severity_threshold": "HIGH"}},
    ),
    (
        "global_settings.suppressions",
        {
            "global_settings": {
                "suppressions": [
                    {"path": "src/**", "reason": "vendored", "rule_id": "X"}
                ]
            }
        },
        {"global_settings": {"suppressions": []}},
    ),
    (
        "global_settings.ignore_paths",
        {"global_settings": {"ignore_paths": [{"path": "docs/**", "reason": "docs"}]}},
        {"global_settings": {"ignore_paths": []}},
    ),
    (
        "scanners.bandit.options.severity_threshold",
        {"scanners": {"bandit": {"options": {"severity_threshold": "LOW"}}}},
        {"scanners": {"bandit": {"options": {"severity_threshold": "HIGH"}}}},
    ),
    (
        "content_db_staleness",
        {"content_db_staleness": "warn"},
        {"content_db_staleness": "fail"},
    ),
    (
        "content_db_staleness_overrides",
        {
            "content_db_staleness_overrides": [
                {
                    "database": "grype-db",
                    "policy": "warn",
                    "expiration": "2099-01-01",
                    "reason": "upstream paused",
                }
            ]
        },
        {"content_db_staleness_overrides": []},
    ),
]


class TestVerdictSettings:
    @pytest.mark.parametrize(
        "key, first, second",
        VERDICT_DISAGREEMENTS,
        ids=[entry[0] for entry in VERDICT_DISAGREEMENTS],
    )
    def test_shards_that_disagree_are_refused(self, harness, key, first, second):
        paths = _write_each(harness, build_shards(2), [first, second])

        result = harness.merge(paths)

        assert result.exit_code == 3, (result.output, result.exception)
        console = " ".join(re.sub(r"\x1b\[[0-9;]*m", "", result.output).split())
        assert key in console, console
        assert "shard 0" in console and "shard 1" in console, console
        assert not (harness.output_dir / RESULTS_FILE_NAME).exists()

    def test_a_disagreement_in_the_last_of_three_shards_is_refused(self, harness):
        """Every shard is compared, not only the first two."""
        paths = _write_each(
            harness,
            build_shards(3),
            [{"fail_on_findings": True}] * 2 + [{"fail_on_findings": False}],
        )

        result = harness.merge(paths)

        assert result.exit_code == 3, (result.output, result.exception)
        console = " ".join(re.sub(r"\x1b\[[0-9;]*m", "", result.output).split())
        assert "fail_on_findings" in console and "shard 2" in console, console

    def test_an_override_settles_a_disagreement(self, harness):
        paths = _write_each(
            harness,
            build_shards(2),
            [{"fail_on_findings": False}, {"fail_on_findings": True}],
        )

        result = harness.merge(paths, "--config-overrides", "fail_on_findings=true")

        _assert_merged(result, harness)

    @pytest.mark.parametrize(
        "flag, exit_code", [("--fail-on-findings", 2), ("--no-fail-on-findings", 0)]
    )
    def test_the_fail_on_findings_flag_settles_a_disagreement(
        self, harness, flag, exit_code
    ):
        """The flag decides fail_on_findings for the merge, so the shards' values don't."""
        paths = _write_each(
            harness,
            build_shards(2),
            [{"fail_on_findings": False}, {"fail_on_findings": True}],
        )

        result = harness.merge(paths, flag)

        assert result.exit_code == exit_code, (result.output, result.exception)
        assert (harness.output_dir / RESULTS_FILE_NAME).is_file()

    @pytest.mark.parametrize("shard_zero", [True, False])
    def test_a_disagreement_is_refused_before_the_completion_gate(
        self, harness, shard_zero
    ):
        """Exit 3 whichever value shard 0 records, though a shard completed nothing.

        The completion gate reads shard 0's ``fail_on_incomplete_scanners``. If it
        ran first, shard 0's value would choose between the gate's exit 1 and the
        disagreement's exit 3.
        """
        shards = build_shards(3)
        _make_shard_contribute_nothing(shards[1])
        paths = _write_each(
            harness,
            shards,
            [
                {"fail_on_incomplete_scanners": shard_zero},
                {"fail_on_incomplete_scanners": not shard_zero},
                {"fail_on_incomplete_scanners": not shard_zero},
            ],
        )

        result = harness.merge(paths)

        assert result.exit_code == 3, (result.output, result.exception)
        console = " ".join(re.sub(r"\x1b\[[0-9;]*m", "", result.output).split())
        assert "fail_on_incomplete_scanners" in console, console

    def test_the_incomplete_scanners_flag_settles_a_disagreement(self, harness):
        paths = _write_each(
            harness,
            build_shards(2),
            [
                {"fail_on_incomplete_scanners": False},
                {"fail_on_incomplete_scanners": True},
            ],
        )

        result = harness.merge(paths, "--no-fail-on-incomplete-scanners")

        _assert_merged(result, harness)

    def test_the_refusal_names_the_flag_that_would_settle_it(self, harness):
        paths = _write_each(
            harness,
            build_shards(2),
            [{"fail_on_findings": False}, {"fail_on_findings": True}],
        )

        result = harness.merge(paths)

        assert result.exit_code == 3, (result.output, result.exception)
        console = " ".join(re.sub(r"\x1b\[[0-9;]*m", "", result.output).split())
        assert "--fail-on-findings" in console, console
        assert "--no-fail-on-findings" in console, console

    def test_a_verdict_setting_in_the_operators_config_is_named(self, harness):
        """The shards' value applies, and the warning gives the override that would not."""
        shard_paths = harness.write_shards({"fail_on_findings": False})
        operator = _write_yaml(
            harness.tmp_path / "operator" / "ash.yaml", {"fail_on_findings": True}
        )

        result = harness.merge(shard_paths, "--config", str(operator))

        assert result.exit_code == 0, (result.output, result.exception)
        named = [m for m in harness.warnings if "fail_on_findings" in m]
        assert named, harness.warnings
        assert "--config-overrides fail_on_findings=true" in named[0]
        assert "--fail-on-findings" in named[0]

    def test_the_suggested_override_carries_no_internal_marker(self, harness):
        """The suppression list it suggests is the operator's, without client_supplied."""
        shard_paths = harness.write_shards({"project_name": "test-merge"})
        suppression = {"path": "src/**", "reason": "vendored", "rule_id": "X"}
        operator = _write_yaml(
            harness.tmp_path / "operator" / "ash.yaml",
            {"global_settings": {"suppressions": [suppression]}},
        )

        result = harness.merge(shard_paths, "--config", str(operator))

        _assert_merged(result, harness)
        named = [
            m
            for m in harness.warnings
            if "ash merge's --config sets global_settings.suppressions" in m
        ]
        assert named, harness.warnings
        assert "client_supplied" not in named[0], named[0]
        assert '"rule_id": "X"' in named[0], named[0]

    def test_the_same_suppressions_in_the_operators_config_are_not_reported(
        self, harness
    ):
        suppression = {"path": "src/**", "reason": "vendored", "rule_id": "X"}
        shard_paths = harness.write_shards(
            {"global_settings": {"suppressions": [suppression]}}
        )
        operator = _write_yaml(
            harness.tmp_path / "operator" / "ash.yaml",
            {"global_settings": {"suppressions": [suppression]}},
        )

        result = harness.merge(shard_paths, "--config", str(operator))

        _assert_merged(result, harness)
        assert not [
            m
            for m in harness.warnings
            if "ash merge's --config sets global_settings.suppressions" in m
        ], harness.warnings

    def test_a_flag_that_decides_the_setting_leaves_no_config_warning(self, harness):
        """--fail-on-findings applies, so the --config value is not reported as ignored."""
        shard_paths = harness.write_shards({"fail_on_findings": False})
        operator = _write_yaml(
            harness.tmp_path / "operator" / "ash.yaml", {"fail_on_findings": True}
        )

        result = harness.merge(
            shard_paths, "--config", str(operator), "--fail-on-findings"
        )

        assert result.exit_code == 2, (result.output, result.exception)
        assert not [
            m
            for m in harness.warnings
            if "ash merge's --config sets fail_on_findings" in m
        ], harness.warnings

    def test_an_operator_config_that_sets_no_verdict_setting_names_none(self, harness):
        """Control: a --config that sets only reporters warns about no verdict setting."""
        shard_paths = harness.write_shards(
            {
                "fail_on_findings": False,
                "global_settings": {
                    "suppressions": [{"path": "src/**", "reason": "r", "rule_id": "X"}]
                },
            }
        )
        operator = _write_yaml(
            harness.tmp_path / "operator" / "ash.yaml",
            {"reporters": {"s3": {"enabled": False}}},
        )

        result = harness.merge(shard_paths, "--config", str(operator))

        assert result.exit_code == 0, (result.output, result.exception)
        assert not [m for m in harness.warnings if "ash merge's --config sets" in m]


class TestAnOperatorConfigThatNamesNothingReadable:
    """A ``--config`` that is missing, a directory or unparseable exits 3, unmerged."""

    @pytest.mark.parametrize("kind", ["missing", "directory", "unparseable"])
    def test_the_merge_is_refused(self, harness, kind):
        target = harness.tmp_path / "operator" / "ash.yaml"
        if kind == "directory":
            target.mkdir(parents=True)
        elif kind == "unparseable":
            target.parent.mkdir(parents=True)
            target.write_text("reporters: [unclosed\n", encoding="utf-8")
        shard_paths = harness.write_shards({"project_name": "test-merge"})

        result = harness.merge(shard_paths, "--config", str(target))

        assert result.exit_code == 3, (result.output, result.exception)
        console = "".join(re.sub(r"\x1b\[[0-9;]*m", "", result.output).split())
        assert "".join(target.as_posix().split()) in console, result.output
        assert not (harness.output_dir / RESULTS_FILE_NAME).exists()


class TestOperatorConfigOutsideTheRecordedConfig:
    """``--config`` supplies values for what the shards recorded and adds nothing.

    A plugin module or reporter setting the file names that the shards did not
    record does not apply, so each is named in a warning with the override that
    would add it.
    """

    OPERATOR = {
        "ash_plugin_modules": [AWS],
        "reporters": {
            "s3": {
                "enabled": True,
                "options": {
                    "bucket_name": "operator-bucket",
                    "aws_region": "us-east-2",
                },
            }
        },
    }

    def test_a_module_and_reporter_the_shards_did_not_record_are_named(self, harness):
        shard_paths = harness.write_shards({"project_name": "test-merge"})
        operator = _write_yaml(
            harness.tmp_path / "operator" / "ash.yaml", self.OPERATOR
        )

        result = harness.merge(shard_paths, "--config", str(operator))

        _assert_merged(result, harness)
        assert harness.loaded_modules == [[]]
        assert harness.uploads == []
        module = [m for m in harness.warnings if f'ash_plugin_modules+=["{AWS}"]' in m]
        assert module, harness.warnings
        assert "--config-overrides" in module[0]
        bucket = [
            m
            for m in harness.warnings
            if "--config-overrides reporters.s3.options.bucket_name=operator-bucket"
            in m
        ]
        assert bucket, harness.warnings
        assert any(
            "--config-overrides reporters.s3.options.aws_region=us-east-2" in m
            for m in harness.warnings
        ), harness.warnings

    def test_values_the_recorded_config_takes_are_not_named(self, harness):
        """Control: the shards record the module and an S3 section, so all of it applies."""
        shard_paths = harness.write_shards(
            {"ash_plugin_modules": [AWS], "reporters": {"s3": {"enabled": True}}}
        )
        operator = _write_yaml(
            harness.tmp_path / "operator" / "ash.yaml", self.OPERATOR
        )

        result = harness.merge(shard_paths, "--config", str(operator))

        _assert_merged(result, harness)
        assert harness.loaded_modules == [[AWS]]
        assert harness.options(harness.S3Reporter)["bucket_name"] == "operator-bucket"
        assert not [m for m in harness.warnings if "does not apply" in m], (
            harness.warnings
        )


class TestTheRealChain:
    """``ash merge`` in a fresh process, with nothing patched.

    The harness above hands the merge the AWS reporter classes whatever it loads.
    Here the plugin loader and registry are the real ones, so what a refused
    package does is measured: it is not imported, and no AWS reporter is
    registered. The control names the package from the operator's side and turns
    off the three AWS reporters whose dependency checks call AWS, so it makes no
    AWS call either; S3 has no bucket, and its check stops before calling AWS.
    """

    _DRIVER = (
        "import json, sys\n"
        "from typer.testing import CliRunner\n"
        "from automated_security_helper.cli.main import app\n"
        "from automated_security_helper.plugins import ash_plugin_manager\n"
        "result = CliRunner().invoke(app, json.loads(sys.argv[1]))\n"
        "reporters = [\n"
        "    f'{cls.__module__}.{cls.__name__}'\n"
        "    for cls in ash_plugin_manager.plugin_modules(plugin_type='reporter')\n"
        "]\n"
        "print('RESULT ' + json.dumps({\n"
        "    'exit': result.exit_code,\n"
        f"    'imported': sorted(m for m in sys.modules if m.startswith({AWS!r})),\n"
        "    'reporters': reporters,\n"
        "    'output': result.output[-3000:],\n"
        "}))\n"
    )

    def _run(self, tmp_path: Path, extra_args: Sequence[str]) -> Dict[str, Any]:
        import os
        import subprocess
        import sys

        from tests.utils.helpers import importing_this_checkout

        collector = tmp_path / "collector"
        collector.mkdir(exist_ok=True)
        recorded_file = _write_yaml(
            tmp_path / "shard-config" / "ash.yaml", SHARD_CONFIG
        )
        recorded = resolve_config(config_path=recorded_file)
        argv = ["merge"]
        for index, model in enumerate(build_shards(2)):
            model.ash_config = recorded
            target = tmp_path / "artifacts" / f"shard-{index}"
            model.save_model(target)
            argv += ["--results", str(target / RESULTS_FILE_NAME)]
        output_dir = tmp_path / f"merged-{len(extra_args)}"
        argv += ["--output-dir", str(output_dir), *extra_args]
        environment = {
            name: value
            for name, value in os.environ.items()
            if not name.startswith(("AWS_", "ASH_"))
        }
        run = subprocess.run(
            [
                sys.executable,
                "-I",
                "-c",
                importing_this_checkout(self._DRIVER),
                json.dumps(argv),
            ],
            cwd=collector,
            env=environment,
            capture_output=True,
            text=True,
            timeout=600,
        )
        assert run.returncode == 0, (run.returncode, run.stderr[-3000:])
        line = [row for row in run.stdout.splitlines() if row.startswith("RESULT ")]
        assert line, (run.stdout[-3000:], run.stderr[-3000:])
        measured = json.loads(line[-1][len("RESULT ") :])
        measured["output_dir"] = output_dir
        return measured

    def test_a_refused_package_is_not_imported_and_registers_no_reporter(
        self, tmp_path
    ):
        measured = self._run(tmp_path, [])

        assert measured["exit"] == 2, measured["output"]
        assert measured["imported"] == []
        assert not [name for name in measured["reporters"] if name.startswith(AWS)]
        assert not (measured["output_dir"] / "reports" / "ash.s3.json").exists()

    def test_control_the_package_the_operator_names_is_imported(self, tmp_path):
        measured = self._run(
            tmp_path,
            [
                "--config-overrides",
                f'ash_plugin_modules=["{AWS}"]',
                "--config-overrides",
                "reporters.aws-security-hub.enabled=false",
                "--config-overrides",
                "reporters.bedrock-summary-reporter.enabled=false",
                "--config-overrides",
                "reporters.cloudwatch-logs.enabled=false",
            ],
        )

        assert measured["exit"] == 2, measured["output"]
        assert AWS in measured["imported"]
        assert f"{AWS}.s3_reporter.S3Reporter" in measured["reporters"]
        assert not (measured["output_dir"] / "reports" / "ash.s3.json").exists()
