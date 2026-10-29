# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""``ash report`` builds an off-host reporter from the section a scan builds it from.

A scan's report phase gives each reporter the section ``reporter_section``
returns (``config/operator_only_options.py``). For a reporter that sends findings
off the host, when a file the scanned repository could write is part of the
configuration, that section is the operator's whole: its ``enabled`` and every
option it set. What the repository's file set for that reporter beyond that is
not used.

``ash report`` reads the section once, through ``reporter_section``, refuses an
off-host reporter that is not enabled from it, and builds the reporter from it.
The resolved section keeps the options of the repository's file that the
confinement does not replace. For S3 that is ``file_format``, which is not one of
the destination options, so reading the resolved section would hand a reporter the
operator had enabled an option a scan would have left out.

In ``ash report`` an off-host reporter runs, and sends where it does, only as
``--config-overrides`` say: stored results do not record which tree was scanned,
so a config file does not choose it (``confine_off_host_reporters_to_overrides``).
``reporter_section`` takes the operator's view that ``resolve_config`` recorded,
and a ``--config`` file outside every tree that ``extends`` a file inside one is in
that view. The same confinement is applied to the view, so the one section the
command reads already has the file's ``enabled`` and destination options replaced
by the overrides'. A refusal on it is the command's refusal, and it says so in the
words of the CLI reference.

The reporter class is S3's, its ``report`` replaced by a stub, and every
botocore request is refused with no credentials and a loopback endpoint, so
nothing here sends anywhere. The tests assert on the ``config`` the reporter was
constructed with.
"""

import copy
from pathlib import Path
from typing import Any, List, NamedTuple, Optional

import botocore.client
import botocore.exceptions
import pytest
import typer

from automated_security_helper.base.reporter_plugin import off_host_reporter_refused
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.config.operator_only_options import reporter_section
from automated_security_helper.config.reporter_trust import (
    REPORTER_DESTINATION_OPTIONS,
    confine_off_host_reporters_to_overrides,
)
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.config.untrusted_source import REPORT_CONFIG_FILE
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter import (
    S3Reporter,
)
from tests.utils.secret_bearing_scan import isolate_from_aws

pytestmark = pytest.mark.unit

AWS_PLUGIN_MODULE = "automated_security_helper.plugin_modules.ash_aws_plugins"
OPERATOR_BUCKET = "operator-bucket"
OPERATOR_REGION = "us-west-2"

#: The scanned repository's own config, in its working directory. It enables S3
#: with its own bucket and sets ``file_format``, an S3 option the confinement of
#: the destination options leaves in the resolved section.
REPOSITORY_CONFIG = (
    "reporters:\n"
    "  s3:\n"
    "    enabled: true\n"
    "    options:\n"
    "      bucket_name: repository-bucket\n"
    "      aws_region: eu-west-1\n"
    "      max_retries: 0\n"
    "      file_format: yaml\n"
)

#: Where the repository's config sits, relative to the working directory.
REPOSITORY_CONFIG_PATH = ".ash/.ash.yaml"

#: How the refusal begins, in every wording the command has had.
REFUSAL_START = "reporter 's3' sends findings off the host and is not enabled"
#: The refusal as the CLI reference describes the command.
REFUSAL = (
    f"{REFUSAL_START}. ash report takes whether it runs, and where it sends, "
    "from --config-overrides"
)
#: Advice an older wording gave, which `ash report` does not honor: it ignores a
#: config file's ``enabled`` for these reporters.
OLD_ADVICE = "Enable it in an operator config"


class Layout(NamedTuple):
    work: Path
    output_dir: Path


def _squeezed(text: str) -> str:
    """*text* without its whitespace: rich folds a long line at the console width."""
    return "".join(text.split())


def _layout(tmp_path: Path, repository_config: Optional[str]) -> Layout:
    """A working directory holding stored results and, when given, the repository's config.

    The working directory is in no git checkout of its own, so the config under
    it is a file the scanned repository could write whatever the checkout above
    the test directory is.
    """
    work = tmp_path / "work"
    output_dir = work / ".ash" / "ash_output"
    output_dir.mkdir(parents=True)
    stored = AshAggregatedResults()
    stored.ash_config = get_default_config()
    (output_dir / "ash_aggregated_results.json").write_text(
        stored.model_dump_json(by_alias=True), encoding="utf-8"
    )
    if repository_config is not None:
        (work / REPOSITORY_CONFIG_PATH).write_text(repository_config, encoding="utf-8")
    return Layout(work, output_dir)


def _outside_every_checkout(path: Path) -> None:
    """Precondition: no directory holding ``path`` is a git checkout.

    Inside one, the file would be held to the repository's rules for that reason
    alone, and the test of a file nothing else marks would pass vacuously.
    """
    holding = [path, *path.parents]
    assert not any((p / ".git").exists() for p in holding), holding


def _operator_overrides(enabled: bool = True) -> List[str]:
    """The operator's ``--config-overrides``: the AWS module, and S3 enabled and aimed."""
    overrides = [f"ash_plugin_modules=[{AWS_PLUGIN_MODULE}]"]
    if enabled:
        overrides += [
            "reporters.s3.enabled=true",
            f"reporters.s3.options.bucket_name={OPERATOR_BUCKET}",
            f"reporters.s3.options.aws_region={OPERATOR_REGION}",
            "reporters.s3.options.max_retries=0",
        ]
    return overrides


@pytest.fixture
def nothing_is_sent(monkeypatch, tmp_path) -> List[str]:
    """No credentials, a loopback endpoint, and every botocore request refused and recorded."""
    isolate_from_aws(monkeypatch, tmp_path)
    for name in ("ASH_CONFIG", "ASH_PLUGIN_MODULES", "ASH_S3_BUCKET_NAME"):
        monkeypatch.delenv(name, raising=False)
    made: List[str] = []

    def refusing_request(client, operation_name, api_params):
        made.append(f"{client.meta.service_model.service_name}.{operation_name}")
        raise botocore.exceptions.ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "refused by the test"}},
            operation_name,
        )

    monkeypatch.setattr(botocore.client.BaseClient, "_make_api_call", refusing_request)
    return made


@pytest.fixture
def built_with(monkeypatch) -> List[Any]:
    """The ``config`` argument of every S3 reporter the command builds, None for none given.

    ``report`` is replaced by a stub, so a reporter that is built and run sends
    nothing and writes a fixed text.
    """
    seen: List[Any] = []
    real_init = S3Reporter.__init__

    def recording_init(self, **data):
        seen.append(copy.deepcopy(data.get("config")))
        real_init(self, **data)

    monkeypatch.setattr(S3Reporter, "__init__", recording_init)
    monkeypatch.setattr(S3Reporter, "report", lambda self, model: "the report")
    return seen


def _sections(built_with: List[Any]) -> List[Any]:
    """The configs the command passed on purpose: the lookup that finds the reporter passes none."""
    return [config for config in built_with if config is not None]


def _report(output_dir: Path, overrides: List[str], config: Optional[str]) -> int:
    """Run ``ash report --format s3`` in this process and return its exit code.

    Called directly rather than through CliRunner, as
    tests/unit/cli/test_report_config_file_does_not_send_off_host.py does: a
    record pytest's live logging writes during an invoke swaps sys.stdout under
    CliRunner.
    """
    from automated_security_helper.cli.report import report_command
    from automated_security_helper.core.enums import AshLogLevel

    try:
        report_command(
            report_format="s3",
            output_dir=str(output_dir),
            log_level=AshLogLevel.ERROR,
            config=config,
            config_overrides=list(overrides),
            verbose=False,
            debug=False,
            color=False,
        )
    except typer.Exit as exit_:
        return int(exit_.exit_code)
    return 0


def _split_destinations(section: Any) -> tuple:
    """``section`` apart: everything but the destination options, and those options.

    The destination options of a section are the ones the confinement takes from
    the overrides (``REPORTER_DESTINATION_OPTIONS``); the rest of it is not.
    """
    destinations = set(REPORTER_DESTINATION_OPTIONS["s3"])
    options = dict(section.get("options") or {})
    others = {k: v for k, v in options.items() if k not in destinations}
    return {**section, "options": others}, {
        k: v for k, v in options.items() if k in destinations
    }


def _the_scans_section(
    config: Optional[str], overrides: List[str], output_dir: Path
) -> tuple:
    """The resolved configuration, and the section a scan's report phase builds S3 from.

    Resolved as ``ash report`` resolves it, so both read the same files.
    """
    resolved = resolve_config(
        config_path=config,
        config_overrides=list(overrides),
        fallback_to_default=config is None,
        also_scanned=[output_dir],
    )
    return resolved, reporter_section(resolved, S3Reporter)


class TestTheReporterIsBuiltFromTheSectionAScanUses:
    def test_the_operators_section_is_used_whole_where_the_repository_wrote_one_too(
        self, tmp_path, monkeypatch, nothing_is_sent, built_with
    ):
        """The case the second read broke: both write S3's section, the operator enables it.

        The resolved section holds the operator's destination (the confinement
        puts it there) and also the repository's ``file_format``. The section a
        scan builds the reporter from is the operator's alone.
        """
        layout = _layout(tmp_path, REPOSITORY_CONFIG)
        monkeypatch.chdir(layout.work)
        overrides = _operator_overrides()
        resolved, scan_section = _the_scans_section(
            REPOSITORY_CONFIG_PATH, overrides, layout.output_dir
        )
        # The setup does what the test needs: the repository's file is one a scan
        # confines, so the operator's configuration is recorded, and the two reads
        # of the section differ. Without these a pass would say nothing.
        assert resolved._operator_reporters is not None
        resolved_section = resolved.get_plugin_config(
            plugin_type="reporter", plugin_name="s3"
        )
        assert resolved_section != scan_section, (resolved_section, scan_section)
        assert resolved_section["options"]["file_format"] == "yaml", resolved_section

        code = _report(layout.output_dir, overrides, REPOSITORY_CONFIG_PATH)

        assert code == 0
        sections = _sections(built_with)
        assert len(sections) == 1, built_with
        built = sections[0]
        assert built["enabled"] is True
        # Compared apart: the keys that say where it sends are the overrides',
        # every other key is the scan's section's.
        scan_rest, scan_destinations = _split_destinations(scan_section)
        built_rest, built_destinations = _split_destinations(built)
        assert built_rest == scan_rest, (built, scan_section)
        assert built_destinations == scan_destinations, (built, scan_section)
        assert built["options"]["bucket_name"] == OPERATOR_BUCKET
        assert built["options"]["aws_region"] == OPERATOR_REGION
        assert "file_format" not in built["options"], built
        assert nothing_is_sent == []


class TestWhatTheConfinedReadKeeps:
    def test_a_section_only_the_operator_wrote_is_the_same_either_way(
        self, tmp_path, monkeypatch, nothing_is_sent, built_with
    ):
        """Control: no file of the repository is in the configuration.

        Nothing is recorded as the operator's view then, and ``reporter_section``
        answers what ``get_plugin_config`` answers, so reading it once or twice
        gives the reporter the same section.
        """
        layout = _layout(tmp_path, None)
        monkeypatch.chdir(layout.work)
        overrides = _operator_overrides()
        resolved, scan_section = _the_scans_section(None, overrides, layout.output_dir)
        assert resolved._operator_reporters is None
        assert (
            resolved.get_plugin_config(plugin_type="reporter", plugin_name="s3")
            == scan_section
        )

        code = _report(layout.output_dir, overrides, None)

        assert code == 0
        sections = _sections(built_with)
        assert len(sections) == 1, built_with
        assert sections[0] == scan_section
        assert sections[0]["enabled"] is True
        assert sections[0]["options"]["bucket_name"] == OPERATOR_BUCKET
        assert nothing_is_sent == []

    @pytest.mark.parametrize(
        "repository_config",
        [None, REPOSITORY_CONFIG],
        ids=["nothing-wrote-it", "the-repository-enables-it"],
    )
    def test_an_off_host_reporter_the_operator_did_not_enable_is_refused(
        self,
        tmp_path,
        monkeypatch,
        nothing_is_sent,
        built_with,
        capfd,
        repository_config,
    ):
        """Control: refused, and not built.

        The repository's file turning S3 on is not the operator turning it on.
        Only the start of the message is compared, which every wording of it
        shares.
        """
        layout = _layout(tmp_path, repository_config)
        monkeypatch.chdir(layout.work)
        config = REPOSITORY_CONFIG_PATH if repository_config is not None else None

        code = _report(layout.output_dir, _operator_overrides(enabled=False), config)

        printed = _squeezed("".join(capfd.readouterr()))
        assert code == 1
        assert _squeezed(REFUSAL_START) in printed, printed
        assert _sections(built_with) == []
        assert nothing_is_sent == []


class TestTheRefusalKeepsTheGuardOnConfigFiles:
    def test_a_config_file_outside_every_tree_that_extends_one_inside_cannot_enable_it(
        self, tmp_path, monkeypatch, nothing_is_sent, built_with, capfd
    ):
        """The case the operator's view alone would let through.

        The operator's file is outside every tree and extends the repository's
        file under the working directory, so ``resolve_config`` records its S3
        section as the operator's view with ``enabled: true``. ``ash report``
        takes whether the reporter runs from ``--config-overrides`` only, so
        once the confinement has run, the section ``reporter_section`` returns
        (the file's ``enabled`` replaced by the default) refuses it.
        """
        layout = _layout(tmp_path, "project_name: from-the-repository\n")
        operator_file = tmp_path / "operator.yaml"
        operator_file.write_text(
            "extends: work/.ash/.ash.yaml\n"
            "reporters:\n"
            "  s3:\n"
            "    enabled: true\n"
            "    options:\n"
            "      bucket_name: operator-file-bucket\n"
            f"      aws_region: {OPERATOR_REGION}\n"
            "      max_retries: 0\n",
            encoding="utf-8",
        )
        _outside_every_checkout(operator_file)
        monkeypatch.chdir(layout.work)
        overrides = _operator_overrides(enabled=False)
        resolved, scan_section = _the_scans_section(
            str(operator_file), overrides, layout.output_dir
        )
        confine_off_host_reporters_to_overrides(
            resolved, [operator_file], overrides, REPORT_CONFIG_FILE
        )
        confined_section = resolved.get_plugin_config(
            plugin_type="reporter", plugin_name="s3"
        )
        # The setup does what the test needs: the operator's view enabled S3
        # before the confinement (scan_section was read then), and neither the
        # resolved section nor the view enables it after. Without the first
        # assert a pass would say nothing about the view.
        assert resolved._operator_reporters is not None
        assert not off_host_reporter_refused(S3Reporter, scan_section), scan_section
        assert off_host_reporter_refused(S3Reporter, confined_section), confined_section
        confined_view = reporter_section(resolved, S3Reporter)
        assert off_host_reporter_refused(S3Reporter, confined_view), confined_view

        code = _report(layout.output_dir, overrides, str(operator_file))

        printed = _squeezed("".join(capfd.readouterr()))
        assert code == 1
        assert _squeezed(REFUSAL) in printed, printed
        assert _sections(built_with) == []
        assert nothing_is_sent == []


class TestTheRefusalSaysWhatTheCliReferenceSays:
    def test_it_sends_the_operator_to_config_overrides(
        self, tmp_path, monkeypatch, nothing_is_sent, built_with, capfd
    ):
        """An older wording told the operator to enable it in a config.

        ``ash report`` ignores a config file's ``enabled`` for these reporters,
        so that advice could not work. The message names ``--config-overrides``
        and the destination options, as the CLI reference does.
        """
        layout = _layout(tmp_path, None)
        monkeypatch.chdir(layout.work)

        code = _report(layout.output_dir, _operator_overrides(enabled=False), None)

        printed = _squeezed("".join(capfd.readouterr()))
        assert code == 1
        assert _squeezed(REFUSAL) in printed, printed
        assert _squeezed("--config-overrides reporters.s3.enabled=true") in printed
        assert _squeezed(OLD_ADVICE) not in printed, printed
        assert _sections(built_with) == []
        assert nothing_is_sent == []


class TestWhereItSendsComesFromTheOverrides:
    def test_a_destination_a_config_file_names_does_not_reach_the_reporter(
        self, tmp_path, monkeypatch, nothing_is_sent, built_with
    ):
        """The overrides enable S3 and aim it nowhere; the files name buckets.

        The repository's file under the working directory names a bucket, and the
        operator's file outside every tree extends it and names another. The
        overrides enable S3, so nothing refuses. The operator's view
        ``resolve_config`` recorded holds the operator's file's bucket, and
        ``ash report`` takes where a report goes from ``--config-overrides``
        alone, so the confinement replaces the destinations in the view as it
        does in the resolved section: the reporter is built with no bucket and
        no region from either file.
        """
        layout = _layout(
            tmp_path,
            "reporters:\n"
            "  s3:\n"
            "    options:\n"
            "      bucket_name: inner-file-bucket\n"
            "      aws_region: eu-west-1\n",
        )
        operator_file = tmp_path / "operator.yaml"
        operator_file.write_text(
            "extends: work/.ash/.ash.yaml\n"
            "reporters:\n"
            "  s3:\n"
            "    options:\n"
            "      bucket_name: operator-file-bucket\n"
            f"      aws_region: {OPERATOR_REGION}\n",
            encoding="utf-8",
        )
        _outside_every_checkout(operator_file)
        monkeypatch.chdir(layout.work)
        overrides = [*_operator_overrides(enabled=False), "reporters.s3.enabled=true"]
        resolved, scan_section = _the_scans_section(
            str(operator_file), overrides, layout.output_dir
        )
        confine_off_host_reporters_to_overrides(
            resolved, [operator_file], overrides, REPORT_CONFIG_FILE
        )
        confined_section = resolved.get_plugin_config(
            plugin_type="reporter", plugin_name="s3"
        )
        # The setup does what the test needs: the operator's view is recorded and
        # held the operator's file's bucket before the confinement (scan_section
        # was read then), the overrides enabled S3, and after the confinement
        # neither the resolved section nor the view names a bucket. Without
        # these a pass would say nothing.
        assert resolved._operator_reporters is not None
        assert not off_host_reporter_refused(S3Reporter, scan_section), scan_section
        assert not off_host_reporter_refused(S3Reporter, confined_section)
        assert scan_section["options"]["bucket_name"] == "operator-file-bucket"
        assert "bucket_name" not in (confined_section.get("options") or {})
        confined_view = reporter_section(resolved, S3Reporter)
        assert not off_host_reporter_refused(S3Reporter, confined_view), confined_view
        assert "bucket_name" not in (confined_view.get("options") or {}), confined_view

        code = _report(layout.output_dir, overrides, str(operator_file))

        assert code == 0
        sections = _sections(built_with)
        assert len(sections) == 1, built_with
        assert sections[0]["enabled"] is True
        options = sections[0].get("options") or {}
        assert "bucket_name" not in options, sections[0]
        assert "aws_region" not in options, sections[0]
        assert "inner-file-bucket" not in repr(sections[0])
        assert "operator-file-bucket" not in repr(sections[0])
        assert nothing_is_sent == []
