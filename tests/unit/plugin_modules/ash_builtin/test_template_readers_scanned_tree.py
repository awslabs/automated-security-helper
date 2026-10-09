# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""cfn-nag and cdk-nag read templates only from inside the scanned tree, and their logs
do not quote templates.

Both scanners parse every JSON and YAML file in the scan set with
``get_model_from_template`` before deciding whether it is CloudFormation, and cdk-nag
then synthesizes the template into its output directory. A template in the tree that is
a symlink to a host file would otherwise have that file parsed, logged in part, handed
to ``cfn_nag_scan`` and copied into cdk-nag's synth output.

The second half covers the log lines themselves. A pydantic ``ValidationError`` quotes
the rejected value and a PyYAML error quotes the offending line; both reached
``ash.log``. They are now named by file, error type and, where the parser knows it, line.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from unittest.mock import create_autospec, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    cdk_nag_scanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (
    CdkNagScanner,
    CdkNagScannerConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_nag_scanner import (
    CfnNagScanner,
    CfnNagScannerConfig,
)
from automated_security_helper.utils import cdk_nag_wrapper as wrapper_module
from automated_security_helper.utils.cdk_nag_wrapper import CdkNagWrapperResponse
from automated_security_helper.utils.cfn_template_model import (
    CloudFormationTemplateModelError,
    get_model_from_template,
)

# Names this change adds are imported inside the tests that use them, so that on a
# tree without them each test fails on its own assertion rather than the whole module
# failing to collect.

MARKER = "HOST-ONLY-CONTENT-a41f"

VALID_TEMPLATE = f"""Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: {MARKER.lower()}
"""

# Carries a Resources mapping the model rejects, with the marker in the rejected value.
UNMODELABLE_TEMPLATE = f"Resources:\n  Bad:\n    Type: 'bad type {MARKER}'\n"

# Not parseable; PyYAML quotes the offending line, which holds the marker.
MALFORMED_TEMPLATE = f"Resources:\n  Bad: [{MARKER}\n  Other: 1\n"

CLEAN_SARIF = json.dumps(
    {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "cfn_nag", "rules": []}}, "results": []}],
    }
)

needs_symlinks = pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)


@pytest.fixture
def ash_records():
    """Every record the 'ash' logger emits, at every level including TRACE."""
    records: list[logging.LogRecord] = []

    class _Collector(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _Collector(level=1)
    logger = logging.getLogger("ash")
    previous = logger.level
    logger.addHandler(handler)
    logger.setLevel(1)
    try:
        yield records
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous)


def logged(records) -> str:
    return "\n".join(r.getMessage() for r in records)


@pytest.fixture
def plugin_context(tmp_path):
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    for directory in (context.source_dir, context.output_dir, context.work_dir):
        directory.mkdir(parents=True)
    return context


@pytest.fixture
def host(tmp_path):
    directory = tmp_path / "host"
    directory.mkdir()
    return directory


def tree_files_with_marker(context) -> list[str]:
    """Files under output_dir holding the marker, and any link there.

    A link is reported whatever it points at: something that later copies the output
    directory, such as an artifact upload, would follow it. work_dir is left out: in
    these tests it is an input tree for the "converted" target type, not output.
    """
    hits = []
    for root in (Path(context.output_dir),):
        for path in root.rglob("*"):
            if path.is_symlink():
                hits.append(f"link: {path}")
            elif path.is_file() and MARKER.encode() in path.read_bytes():
                hits.append(str(path))
    return hits


# ---------------------------------------------------------------------------
# get_model_from_template
# ---------------------------------------------------------------------------


class TestTemplateModel:
    @needs_symlinks
    def test_a_symlinked_template_is_refused_before_it_is_read(self, tmp_path, host):
        (host / "t.yaml").write_text(UNMODELABLE_TEMPLATE)
        tree = tmp_path / "tree"
        tree.mkdir()
        (tree / "t.yaml").symlink_to(host / "t.yaml")

        from automated_security_helper.utils.scanned_tree import TreeInputRefused

        with pytest.raises(TreeInputRefused) as excinfo:
            get_model_from_template(tree / "t.yaml", scan_root=tree)

        assert excinfo.value.reason == "it is a symbolic link"

    def test_an_in_tree_template_models_the_same_with_and_without_a_root(
        self, tmp_path
    ):
        (tmp_path / "t.yaml").write_text(VALID_TEMPLATE.replace("\n", "\r\n"))

        with_root = get_model_from_template(tmp_path / "t.yaml", scan_root=tmp_path)
        without_root = get_model_from_template(tmp_path / "t.yaml")

        assert with_root == without_root
        assert with_root is not None
        assert with_root.Resources["Bucket"].Type == "AWS::S3::Bucket"

    def test_a_rejected_template_is_logged_without_its_content(
        self, tmp_path, ash_records
    ):
        (tmp_path / "t.yaml").write_text(UNMODELABLE_TEMPLATE)

        with pytest.raises(CloudFormationTemplateModelError) as excinfo:
            get_model_from_template(tmp_path / "t.yaml", scan_root=tmp_path)

        text = logged(ash_records)
        assert "t.yaml" in text
        assert "ValidationError" in text
        assert MARKER not in text
        assert MARKER not in str(excinfo.value)

    def test_describe_parse_error_keeps_type_and_line_only(self):
        import yaml

        from automated_security_helper.utils.cfn_template_model import (
            describe_parse_error,
        )

        with pytest.raises(yaml.YAMLError) as excinfo:
            yaml.safe_load(MALFORMED_TEMPLATE)

        described = describe_parse_error(excinfo.value)

        assert MARKER in str(excinfo.value), "the raw error quotes the line"
        assert MARKER not in described
        assert described.startswith(type(excinfo.value).__name__)
        assert " at line " in described

    def test_describe_parse_error_reads_a_json_line_number(self):
        from automated_security_helper.utils.cfn_template_model import (
            describe_parse_error,
        )

        with pytest.raises(json.JSONDecodeError) as excinfo:
            json.loads('{\n  "a": 1,\n  "b": \n}')
        assert describe_parse_error(excinfo.value) == "JSONDecodeError at line 4"


# ---------------------------------------------------------------------------
# cfn-nag
# ---------------------------------------------------------------------------


@pytest.fixture
def cfn_nag(plugin_context):
    with (
        patch.object(
            CfnNagScanner,
            "validate_plugin_dependencies",
            autospec=True,
            return_value=True,
        ),
        patch.object(CfnNagScanner, "_run_subprocess", autospec=True) as run,
    ):
        # A clean, well-formed result, so an evaluated template counts as attempted
        # and not as failed.
        run.return_value = {"stdout": CLEAN_SARIF, "stderr": "", "returncode": 0}
        yield CfnNagScanner(context=plugin_context, config=CfnNagScannerConfig()), run


def cfn_nag_inputs(run) -> list[str]:
    """The --input-path each cfn_nag_scan invocation was given."""
    paths = []
    for call in run.call_args_list:
        command = call.kwargs["command"]
        paths.append(command[command.index("--input-path") + 1])
    return paths


class TestCfnNag:
    @needs_symlinks
    @pytest.mark.parametrize("target_type", ["source", "converted"])
    def test_a_symlinked_template_is_skipped_warned_and_recorded(
        self, target_type, cfn_nag, plugin_context, host, ash_records
    ):
        scanner, run = cfn_nag
        root = (
            plugin_context.source_dir
            if target_type == "source"
            else plugin_context.work_dir
        )
        (host / "t.yaml").write_text(UNMODELABLE_TEMPLATE)
        (root / "t.yaml").symlink_to(host / "t.yaml")
        (root / "real.yaml").write_text(
            VALID_TEMPLATE.replace(MARKER.lower(), "in-tree")
        )

        scanner.scan(target=root, target_type=target_type)

        assert [Path(p).name for p in cfn_nag_inputs(run)] == ["real.yaml"]
        assert "Skipped t.yaml: it is a symbolic link" in " ".join(scanner.errors)
        warnings = [r.getMessage() for r in ash_records if r.levelno == logging.WARNING]
        assert any("Skipped t.yaml: it is a symbolic link" in w for w in warnings)
        assert MARKER not in logged(ash_records)
        assert tree_files_with_marker(plugin_context) == []
        # A skipped file is not a failed target: a repository full of symlinked
        # JSON must not turn the scanner red.
        assert scanner.targets_failed == 0
        assert scanner.targets_attempted == 1

    def test_an_unmodelable_template_is_logged_without_its_content(
        self, cfn_nag, plugin_context, ash_records
    ):
        scanner, _ = cfn_nag
        (plugin_context.work_dir / "t.yaml").write_text(UNMODELABLE_TEMPLATE)

        scanner.scan(target=plugin_context.work_dir, target_type="converted")

        assert scanner.targets_failed == 1
        assert MARKER not in logged(ash_records)
        assert MARKER not in " ".join(scanner.errors)

    def test_an_unparseable_file_is_logged_without_its_content(
        self, cfn_nag, plugin_context, ash_records
    ):
        scanner, run = cfn_nag
        (plugin_context.work_dir / "t.yaml").write_text(MALFORMED_TEMPLATE)

        scanner.scan(target=plugin_context.work_dir, target_type="converted")

        run.assert_not_called()
        text = logged(ash_records)
        assert "Not a CloudFormation file" in text
        assert MARKER not in text


# ---------------------------------------------------------------------------
# cdk-nag
# ---------------------------------------------------------------------------


@pytest.fixture
def cdk_nag(plugin_context, monkeypatch, tmp_path):
    monkeypatch.setattr(cdk_nag_scanner, "_CDK_AVAILABLE", True)
    fake_node = tmp_path / "bin" / "node"
    fake_node.parent.mkdir(parents=True)
    fake_node.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    monkeypatch.setattr(cdk_nag_scanner, "find_executable", lambda name: str(fake_node))
    double = create_autospec(
        wrapper_module.run_cdk_nag_against_cfn_template, spec_set=True
    )
    double.return_value = CdkNagWrapperResponse(results={})
    monkeypatch.setattr(cdk_nag_scanner, "run_cdk_nag_against_cfn_template", double)
    return CdkNagScanner(context=plugin_context, config=CdkNagScannerConfig()), double


class TestCdkNag:
    @needs_symlinks
    @pytest.mark.parametrize("target_type", ["source", "converted"])
    def test_a_symlinked_template_never_reaches_the_wrapper(
        self, target_type, cdk_nag, plugin_context, host, ash_records
    ):
        scanner, double = cdk_nag
        root = (
            plugin_context.source_dir
            if target_type == "source"
            else plugin_context.work_dir
        )
        (host / "t.yaml").write_text(VALID_TEMPLATE)
        (root / "t.yaml").symlink_to(host / "t.yaml")
        (root / "real.yaml").write_text(
            VALID_TEMPLATE.replace(MARKER.lower(), "in-tree")
        )

        scanner.scan(target=root, target_type=target_type)

        templates = [
            Path(c.kwargs["template_path"]).name for c in double.call_args_list
        ]
        assert templates == ["real.yaml"]
        # The wrapper is told the root, so it reads the template under the same rule.
        assert double.call_args.kwargs["scan_root"] == root
        assert "Skipped t.yaml: it is a symbolic link" in " ".join(scanner.errors)
        assert scanner.targets_attempted == 1
        assert scanner.targets_failed == 0
        assert MARKER not in logged(ash_records)

    def test_an_unparseable_file_is_logged_without_its_content(
        self, cdk_nag, plugin_context, ash_records
    ):
        import yaml

        scanner, double = cdk_nag
        (plugin_context.work_dir / "t.yaml").write_text(MALFORMED_TEMPLATE)
        try:
            yaml.safe_load(MALFORMED_TEMPLATE)
        except yaml.YAMLError as exc:
            double.side_effect = exc

        scanner.scan(target=plugin_context.work_dir, target_type="converted")

        text = logged(ash_records)
        assert "is not parseable as YAML or JSON" in text
        assert MARKER not in text
        assert MARKER not in " ".join(scanner.errors)


class TestCfnNagReadsTheCheckedText:
    """cfn_nag_scan is given a copy of the text ASH checked, not the tree path."""

    def test_findings_on_the_copy_point_back_at_the_template(
        self, cfn_nag, plugin_context
    ):
        import os

        scanner, run = cfn_nag
        template = plugin_context.source_dir / "infra" / "role.yaml"
        template.parent.mkdir()
        template.write_text(VALID_TEMPLATE.replace(MARKER.lower(), "in-tree"))
        given = []

        def cfn_nag_scan(self, **kwargs):
            command = kwargs["command"]
            staged = Path(command[command.index("--input-path") + 1])
            given.append((staged, staged.read_text()))
            # cfn_nag renders an absolute input path relative to its working
            # directory, which ASH sets to the source directory.
            uri = os.path.relpath(staged, os.path.realpath(plugin_context.source_dir))
            sarif = json.loads(CLEAN_SARIF)
            sarif["runs"][0]["results"] = [
                {
                    "ruleId": "W35",
                    "level": "warning",
                    "message": {"text": "logging"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": Path(uri).as_posix(),
                                    "uriBaseId": "%SRCROOT%",
                                },
                                "region": {"startLine": 3},
                            }
                        }
                    ],
                }
            ]
            return {"stdout": json.dumps(sarif), "stderr": "", "returncode": 0}

        run.side_effect = cfn_nag_scan

        report = scanner.scan(target=plugin_context.source_dir, target_type="source")

        ((staged, text),) = given
        assert staged != template
        assert staged.name == template.name
        assert text == template.read_text()
        assert not staged.exists()
        uris = [
            r.locations[0].physicalLocation.root.artifactLocation.uri
            for r in report.runs[0].results
        ]
        assert uris == ["infra/role.yaml"]


class TestCdkNagWorkerCarriesARefusal:
    def test_a_refusal_in_the_worker_is_re_raised_as_itself(self):
        from automated_security_helper.utils import cdk_nag_worker
        from automated_security_helper.utils.scanned_tree import TreeInputRefused

        refusal = TreeInputRefused("t.yaml", "it changed while it was being checked")
        assert cdk_nag_worker._exception_kind(refusal) == "refused"
        with pytest.raises(TreeInputRefused) as excinfo:
            cdk_nag_worker._raise_as_reported(
                {
                    "status": "raised",
                    "kind": "refused",
                    "type": "TreeInputRefused",
                    "message": str(refusal),
                    "path": refusal.path,
                    "reason": refusal.reason,
                }
            )
        assert (excinfo.value.path, excinfo.value.reason) == (
            "t.yaml",
            "it changed while it was being checked",
        )

    def test_a_late_refusal_is_a_skip_not_a_failed_target(
        self, cdk_nag, plugin_context
    ):
        from automated_security_helper.utils.scanned_tree import TreeInputRefused

        scanner, double = cdk_nag
        (plugin_context.work_dir / "t.yaml").write_text(VALID_TEMPLATE)
        double.side_effect = TreeInputRefused(
            "t.yaml", "it changed while it was being checked"
        )

        scanner.scan(target=plugin_context.work_dir, target_type="converted")

        assert scanner.targets_attempted == 0
        assert scanner.targets_failed == 0
        assert "Skipped t.yaml: it changed while it was being checked" in " ".join(
            scanner.errors
        )
