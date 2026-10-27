# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""``ash merge --config``: the operator's file is read first, and its modules load.

The operator's ``--config`` is the only configuration that can turn on a reporter
that sends findings off the host in a merge (the shards' recorded config is
ignored for those). The tests below check two things about it:

- The merge imports the modules it names in ``ash_plugin_modules``. With a
  ``--config`` naming the AWS plugins and enabling S3, the merge finds the S3
  reporter and uploads to the operator's bucket; modules only the shards recorded
  are not imported. An in-process test of the same thing would pass whatever the
  merge imports, because its module imports an AWS reporter at the top, which
  registers the AWS plugins for the whole worker. These run the merge in a child
  process, where the only modules registered are the ones the merge imports
  itself.
- The file is read before the merged results are written, and a file that does
  not parse refuses the merge with exit 3, as ``ash report`` refuses it.

The child talks to a loopback stand-in for STS and S3 (``AWS_ENDPOINT_URL``) that
records each request and answers the S3 reporter's dependency check, so an
upload the merge attempts is seen, and nothing leaves the machine.
"""

import subprocess
import sys
from pathlib import Path

import pytest

from tests.unit.cli.test_merge import build_shards, write_shards
from tests.utils import aws_stand_in as stand_in
from tests.utils.helpers import importing_this_checkout

AWS_PLUGIN_MODULE = "automated_security_helper.plugin_modules.ash_aws_plugins"


@pytest.fixture
def aws_stand_in():
    """The stand-in's URL and the list of requests it received."""
    with stand_in.aws_stand_in() as served:
        yield served


def _operator_config(path: Path, body: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


ENABLE_S3 = f"""
ash_plugin_modules:
  - {AWS_PLUGIN_MODULE}
reporters:
  s3:
    enabled: true
    options:
      bucket_name: operator-bucket
      aws_region: us-east-1
      max_retries: 0
"""


def _merge_in_a_child(
    tmp_path: Path, endpoint: str, *extra: str, shard_config: dict | None = None
):
    """``ash merge`` over two shards, in a fresh interpreter.

    It runs in ``tmp_path/collector``, the collector job's working directory. A
    --config inside that directory's checkout is one the repository could have
    written, so the operator's own files are kept outside it (``tmp_path/operator``).
    *shard_config*, when given, is the configuration each shard records.
    """
    shards = build_shards(2)
    if shard_config is not None:
        from automated_security_helper.config.ash_config import AshConfig

        for shard in shards:
            shard.ash_config = AshConfig.model_validate(shard_config)
    shards = write_shards(tmp_path / "artifacts", shards)
    env = stand_in.child_aws_env(tmp_path, endpoint)
    collector = tmp_path / "collector"
    collector.mkdir(exist_ok=True)
    argv = [
        sys.executable,
        "-c",
        importing_this_checkout(
            "from automated_security_helper.cli.main import app; app()"
        ),
        "merge",
    ]
    for shard in shards:
        argv += ["--results", shard]
    argv += ["--output-dir", str(tmp_path / "merged"), "--no-color", *extra]
    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=300,
        cwd=collector,
        env=env,
        check=False,
    )


def test_the_operators_config_loads_its_own_plugin_modules(tmp_path, aws_stand_in):
    """The shards name no plugin module; the operator's --config names the AWS
    plugins and enables S3. The upload reaches the operator's bucket."""
    endpoint, requests = aws_stand_in
    config = _operator_config(tmp_path / "operator" / "ash.yaml", ENABLE_S3)

    result = _merge_in_a_child(tmp_path, endpoint, "--config", str(config))

    assert "Traceback" not in result.stderr, result.stderr
    puts = [path for service, path in requests if path.startswith("PutObject")]
    assert puts and all(
        path.startswith("PutObject /operator-bucket/") for path in puts
    ), (
        requests,
        result.stdout,
        result.stderr,
    )


def test_security_hub_imports_under_the_operators_scope_not_the_shards(tmp_path):
    """The shards record Security Hub enabled under their own scope, with
    archiving on; the operator's --config enables it under the operator's. The
    import is under the operator's scope, and nothing is read or archived."""
    bodies: list = []
    shard_config = {
        "ash_plugin_modules": [AWS_PLUGIN_MODULE],
        "reporters": {
            "aws-security-hub": {
                "enabled": True,
                "options": {
                    "aws_region": "us-east-1",
                    "findings_scope": "shard-scope",
                    "archive_resolved_findings": True,
                },
            }
        },
    }
    config = _operator_config(
        tmp_path / "operator" / "ash.yaml",
        f"ash_plugin_modules:\n  - {AWS_PLUGIN_MODULE}\n"
        "reporters:\n  aws-security-hub:\n    enabled: true\n    options:\n"
        "      aws_region: us-east-1\n      findings_scope: operator-scope\n",
    )

    with stand_in.aws_stand_in(security_hub=True, bodies=bodies) as (url, requests):
        result = _merge_in_a_child(
            tmp_path, url, "--config", str(config), shard_config=shard_config
        )

    assert "Traceback" not in result.stderr, result.stderr
    imports = [
        body for what, body in bodies if what.startswith("POST /findings/import")
    ]
    assert imports, (requests, result.stderr[-2000:])
    assert all('"ash/target": "operator-scope"' in body for body in imports), imports
    assert not [body for _, body in bodies if "shard-scope" in body]
    assert not [
        what
        for _, what in requests
        if what == "POST /findings" or what.startswith("PATCH /findings/batchupdate")
    ], requests


def test_a_config_in_the_collectors_checkout_does_not_turn_it_on(
    tmp_path, aws_stand_in
):
    """A --config inside the working directory's tree is one the repository
    could write (a collector job runs in its checkout), so it enables no
    off-host reporter, as in a scan."""
    endpoint, requests = aws_stand_in
    config = _operator_config(tmp_path / "collector" / ".ash" / "ash.yaml", ENABLE_S3)

    result = _merge_in_a_child(tmp_path, endpoint, "--config", str(config))

    assert "Traceback" not in result.stderr, result.stderr
    assert requests == [], (requests, result.stderr)


def test_without_the_operators_config_nothing_is_sent(tmp_path, aws_stand_in):
    """Control: the same merge with no --config contacts nothing."""
    endpoint, requests = aws_stand_in

    result = _merge_in_a_child(tmp_path, endpoint)

    assert "Traceback" not in result.stderr, result.stderr
    assert requests == []


@pytest.mark.parametrize(
    "body",
    ["reporters: [unclosed\n", "reporters:\n  s3:\n    enabled: [true\n"],
    ids=["flow-list", "nested"],
)
def test_an_operator_config_that_does_not_parse_refuses_the_merge(
    tmp_path, aws_stand_in, body
):
    """Exit 3, as `ash report` exits on the same file, and nothing is written."""
    endpoint, requests = aws_stand_in
    config = _operator_config(tmp_path / "operator" / "ash.yaml", body)

    result = _merge_in_a_child(tmp_path, endpoint, "--config", str(config))

    assert result.returncode == 3, (result.stdout, result.stderr)
    assert "Invalid configuration" in result.stdout + result.stderr
    assert not (tmp_path / "merged" / "ash_aggregated_results.json").exists()
    assert requests == []


def test_an_operator_config_that_does_not_validate_refuses_the_merge(
    tmp_path, aws_stand_in
):
    endpoint, requests = aws_stand_in
    config = _operator_config(
        tmp_path / "operator" / "ash.yaml",
        "global_settings:\n  severity_threshold: 7\n",
    )

    result = _merge_in_a_child(tmp_path, endpoint, "--config", str(config))

    assert result.returncode == 3, (result.stdout, result.stderr)
    assert not (tmp_path / "merged" / "ash_aggregated_results.json").exists()
    assert requests == []
