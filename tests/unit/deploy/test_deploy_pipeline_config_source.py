#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Both sharded pipelines judge a repository by the operator's ASH config, never its own.

Why this file exists
--------------------
A shard runs ``ash scan --source-dir <checkout>``. Without ``--config`` or
``ASH_CONFIG``, ASH looks for a config inside the scanned tree, so a repository that
commits one would choose its own scanners, ignore paths and ``fail_on_findings``.
``ash merge`` forms the verdict from the config the shards recorded, so that choice
would reach the pipeline's result too. With no base config, every shard and the merge
are given ``{}`` (ASH's defaults), written outside the checkout.

These tests run the committed buildspecs phase by phase, with this repository's own
``ash``, over a checkout that carries an ASH config. The shard results travel through
a moto S3 server as they do through the results bucket in a deployment. The control
shows that the in-tree config does decide the verdict when ASH is given no config;
the pipeline cases assert that neither the shards' recorded config nor the merge's
verdict comes from it.

``ASH_SCANNERS=detect-secrets`` (the ``--scanners`` option's envvar) keeps each scan
to a few seconds and needs nothing beyond ASH's own dependencies. It does not take
part in choosing the config.
"""

from __future__ import annotations

import base64
import json
import os
import pathlib
import re
import shlex
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest
import yaml

from tests.unit.deploy.codepipeline_stub import CodePipelineStub, action_execution
from tests.unit.deploy.buildspec_extraction import (
    CDK_TEMPLATE_DIR,
    CONTAINER_HELPER_PATH,
    REPO_ROOT,
    TERRAFORM_S3_SYNC,
    load_template,
    phase_commands,
    posix_shell,
)

pytestmark = pytest.mark.skipif(
    os.name == "nt",
    reason="executes POSIX buildspec commands destined for a Linux build container",
)

PIPELINE_TEMPLATE = CDK_TEMPLATE_DIR / "AshDistributedPipeline.template.json"
EXECUTOR = REPO_ROOT / "deploy" / "terraform" / "modules" / "codepipeline-executor"
CONTAINER_INIT = (
    REPO_ROOT
    / "deploy"
    / "terraform"
    / "modules"
    / "ash-image-pipeline"
    / "files"
    / "ash-container-init"
)
CONTAINER_INIT_PATH = "/usr/local/bin/ash-container-init"
#: The value the CDK projects give ASH_CONFIG. Each test moves it into its own
#: directory, as the helper path is moved, so parallel runs cannot share a file.
CDK_CONFIG_PATH = "/tmp/ash-config/.ash.yaml"

IN_TREE_PROJECT_NAME = "in-tree-config"
#: Ignores only the file holding the finding. With every file ignored, detect-secrets
#: has nothing to scan and is SKIPPED, and a run whose scanners were all skipped
#: exits 1, so the control could not show the config turning exit 2 into exit 0.
IN_TREE_CONFIG = (
    f"project_name: {IN_TREE_PROJECT_NAME}\n"
    "fail_on_findings: false\n"
    "global_settings:\n"
    "  ignore_paths:\n"
    '    - path: "deploy.pem"\n'
    '      reason: "listed in the scanned tree"\n'
)

EXECUTION_ID = "exec-config-source"
PIPELINE = "ash-config-source-pipeline"
#: A documentation-example account id, never a real one.
ACCOUNT = "111122223333"


def _build_id(project: str, index: int) -> str:
    return f"{project}:{index:08d}-0000-4000-8000-000000000000"


def _build_arn(build_id: str) -> str:
    return f"arn:aws:codebuild:us-east-1:{ACCOUNT}:build/{build_id}"


def _shard_actions(project: str, count: int) -> list[dict]:
    """What CodePipeline reports for the scan stage: one succeeded build per shard action."""
    return [
        action_execution(
            action=f"Shard{i}",
            status="Succeeded",
            build_id=_build_id(f"{project}-{i}", i),
            execution_id=EXECUTION_ID,
        )
        for i in range(count)
    ]


def _checkout(root: pathlib.Path) -> pathlib.Path:
    """A repository checkout with an ASH config of its own and one finding.

    The finding is a private key block, which detect-secrets reports. It is
    generated per run, and its markers are split in this source, so no key-shaped
    text is committed.
    """
    (root / ".ash").mkdir(parents=True)
    (root / ".ash" / ".ash.yaml").write_text(IN_TREE_CONFIG, encoding="utf-8")
    (root / "app.py").write_text('print("scanned")\n', encoding="utf-8")
    body = base64.b64encode(os.urandom(600)).decode()
    marker = "RSA PRIVATE " + "KEY-----"
    (root / "deploy.pem").write_text(
        f"-----BEGIN {marker}\n{body}\n-----END {marker}\n", encoding="utf-8"
    )
    return root


@pytest.fixture
def ash_env(child_env: dict[str, str], tmp_path: pathlib.Path) -> dict[str, str]:
    """The moto-bound child environment, with this repository's ash and no ASH_* leftovers."""
    env = {k: v for k, v in child_env.items() if not k.startswith("ASH_")}
    home = tmp_path / "home"
    home.mkdir()
    env.update(
        {
            "ASH_SCANNERS": "detect-secrets",
            "HOME": str(home),
            "UV_CACHE_DIR": str(tmp_path / "uv-cache"),
            "XDG_CACHE_HOME": str(home / ".cache"),
            "XDG_CONFIG_HOME": str(home / ".config"),
            "XDG_DATA_HOME": str(home / ".local" / "share"),
        }
    )
    ash = shutil.which("ash", path=env["PATH"])
    assert (
        ash is not None
        and pathlib.Path(ash).parent == pathlib.Path(sys.executable).parent
    ), f"expected this interpreter's ash first on PATH, found {ash!r}"
    return env


def _run_phase(
    commands: list[str], env: dict[str, str], cwd: pathlib.Path
) -> subprocess.CompletedProcess:
    """Run one phase's commands in one shell, stopping at the first that fails."""
    script = "\n".join(
        f'{command}\nash_rc=$?; [ "$ash_rc" -eq 0 ] || exit "$ash_rc"'
        for command in commands
    )
    return subprocess.run(
        [posix_shell(env), "-c", script],
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
    )


def _ok(result: subprocess.CompletedProcess, what: str) -> None:
    assert result.returncode == 0, (
        f"{what} exited {result.returncode}\n"
        f"stdout:\n{result.stdout[-4000:]}\nstderr:\n{result.stderr[-4000:]}"
    )


def _recorded_config(results: dict) -> dict:
    return results.get("ash_config") or {}


def _assert_not_the_in_tree_config(results: dict, where: str) -> None:
    config = _recorded_config(results)
    seen = {
        "project_name": config.get("project_name"),
        "fail_on_findings": config.get("fail_on_findings"),
        "ignore_paths": (config.get("global_settings") or {}).get("ignore_paths"),
    }
    assert seen["project_name"] != IN_TREE_PROJECT_NAME, (
        f"{where} recorded the checkout's own ASH config: {seen!r}"
    )
    assert seen["fail_on_findings"] is not False, (where, seen)
    assert not seen["ignore_paths"], (where, seen)


def _actionable(merge_output: str) -> str:
    """The merge's summary line, for the failure message."""
    return next(
        (line for line in merge_output.splitlines() if "Actionable" in line),
        merge_output[-2000:],
    )


# ---------------------------------------------------------------------------
# Control: the checkout's config changes the verdict when ASH is handed no config
# ---------------------------------------------------------------------------


def test_control_the_in_tree_config_decides_the_verdict_when_ash_is_given_none(
    ash_env: dict[str, str], tmp_path: pathlib.Path
):
    """Without ASH_CONFIG, ASH reads the checkout's file and the finding stops counting.

    The pipeline cases below expect exit 2 from the merge. This shows that the
    fixture's config would turn that into exit 0, so their passing is evidence the
    config was not read rather than evidence the fixture does nothing.
    """
    source = _checkout(tmp_path / "src")

    def shard(index: int) -> subprocess.CompletedProcess:
        return subprocess.run(
            [
                "ash",
                "scan",
                "--source-dir",
                str(source),
                "--output-dir",
                str(tmp_path / f"shard-{index}"),
                "--shard-index",
                str(index),
                "--shard-count",
                "2",
                "--no-fail-on-findings",
                "--no-progress",
                "--simple",
            ],
            cwd=str(source),
            env=ash_env,
            capture_output=True,
            text=True,
            timeout=600,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        for index, result in enumerate(pool.map(shard, range(2))):
            _ok(result, f"control shard {index}")

    for index in range(2):
        results = json.loads(
            (tmp_path / f"shard-{index}" / "ash_aggregated_results.json").read_text(
                encoding="utf-8"
            )
        )
        assert _recorded_config(results).get("project_name") == IN_TREE_PROJECT_NAME

    merge = subprocess.run(
        [
            "ash",
            "merge",
            "--results",
            str(tmp_path / "shard-0"),
            "--results",
            str(tmp_path / "shard-1"),
            "--output-dir",
            str(tmp_path / "merged"),
        ],
        cwd=str(source),
        env=ash_env,
        capture_output=True,
        text=True,
        timeout=600,
    )
    assert merge.returncode == 0, _actionable(merge.stdout + merge.stderr)


# ---------------------------------------------------------------------------
# The CDK sharded pipeline, from the committed template
# ---------------------------------------------------------------------------


def _cdk_projects() -> tuple[list[dict], dict]:
    """The shard projects in index order, and the merge project."""
    template = load_template(PIPELINE_TEMPLATE)
    shards: dict[int, dict] = {}
    merge = None
    for resource in template["Resources"].values():
        if resource.get("Type") != "AWS::CodeBuild::Project":
            continue
        properties = resource["Properties"]
        variables = {
            v["Name"]: v["Value"]
            for v in properties["Environment"].get("EnvironmentVariables", [])
        }
        project = {
            "buildspec": json.loads(properties["Source"]["BuildSpec"])
            if isinstance(properties["Source"].get("BuildSpec"), str)
            else None,
            "variables": variables,
        }
        description = str(properties.get("Description", ""))
        if description.startswith("ASH scan shard "):
            shards[int(variables["ASH_SHARD_INDEX"])] = project
        elif description.startswith("Merges "):
            merge = project
    assert sorted(shards) == list(range(len(shards))) and len(shards) > 1, sorted(
        shards
    )
    assert merge is not None, "no merge project in the committed pipeline template"
    return [shards[i] for i in sorted(shards)], merge


def _cdk_environment(
    project: dict, ash_env: dict[str, str], workdir: pathlib.Path, bucket: str
) -> dict[str, str]:
    """The project's own plain variables, with the per-deployment ones filled in."""
    env = dict(ash_env)
    for name, value in project["variables"].items():
        if isinstance(value, str):
            env[name] = value
    # The config path is the one value relocated, as the helper path is.
    assert env.get("ASH_CONFIG") == CDK_CONFIG_PATH, env.get("ASH_CONFIG")
    env["ASH_CONFIG"] = str(workdir / "ash-config" / ".ash.yaml")
    env["ASH_RESULTS_BUCKET"] = bucket
    # No base config: the stack's default.
    env["ASH_BASE_CONFIG_SSM_PARAMETER"] = ""
    # Set per action by the pipeline.
    env["ASH_RESULTS_PREFIX"] = f"executions/{EXECUTION_ID}"
    env["TMPDIR"] = str(workdir / "tmp")
    (workdir / "tmp").mkdir(parents=True, exist_ok=True)
    return env


def _relocated(commands: list[str], helper: pathlib.Path) -> list[str]:
    return [c.replace(CONTAINER_HELPER_PATH, str(helper)) for c in commands]


def test_the_cdk_pipeline_reads_neither_shard_nor_merge_config_from_the_checkout(
    ash_env: dict[str, str], bucket: str, s3, tmp_path: pathlib.Path
):
    """Every shard records ASH's defaults, and the merge fails on the finding."""
    shards, merge = _cdk_projects()

    def run_shard(index: int) -> None:
        workdir = tmp_path / f"cdk-shard-{index}"
        source = _checkout(workdir / "src")
        env = _cdk_environment(shards[index], ash_env, workdir, bucket)
        env["CODEBUILD_SRC_DIR"] = str(source)
        env["CODEBUILD_BUILD_ARN"] = _build_arn(_build_id(f"cdk-shard-{index}", index))
        helper = workdir / "ash-s3-sync.py"
        for phase in ("pre_build", "build", "post_build"):
            commands = _relocated(
                phase_commands(shards[index]["buildspec"], phase), helper
            )
            _ok(_run_phase(commands, env, source), f"shard {index} {phase}")

    with ThreadPoolExecutor(max_workers=len(shards)) as pool:
        list(pool.map(run_shard, range(len(shards))))

    for index in range(len(shards)):
        build = _build_arn(_build_id(f"cdk-shard-{index}", index))
        key = f"executions/{EXECUTION_ID}/shard-{index}/{build}/ash_aggregated_results.json"
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        _assert_not_the_in_tree_config(json.loads(body), f"CDK shard {index}")

    workdir = tmp_path / "cdk-merge"
    source = _checkout(workdir / "src")
    env = _cdk_environment(merge, ash_env, workdir, bucket)
    env["CODEBUILD_SRC_DIR"] = str(source)
    env["ASH_PIPELINE_EXECUTION_ID"] = EXECUTION_ID
    env["CODEBUILD_INITIATOR"] = f"codepipeline/{PIPELINE}"
    env["CODEBUILD_BUILD_ARN"] = _build_arn(_build_id("cdk-merge", 99))
    helper = workdir / "ash-s3-sync.py"
    pre_build = _relocated(phase_commands(merge["buildspec"], "pre_build"), helper)
    actions = _shard_actions("cdk-shard", len(shards))
    with CodePipelineStub(PIPELINE, actions, page_size=10) as stub:
        env["AWS_ENDPOINT_URL_CODEPIPELINE"] = stub.url
        _ok(_run_phase(pre_build, env, source), "merge pre_build")

    build = _run_phase(
        _relocated(phase_commands(merge["buildspec"], "build"), helper), env, source
    )
    assert build.returncode == 2, (
        f"expected the merge to fail on the finding (exit 2), got {build.returncode}: "
        f"{_actionable(build.stdout + build.stderr)}"
    )
    merged = json.loads(
        (source / "ash-merged-output" / "ash_aggregated_results.json").read_text(
            encoding="utf-8"
        )
    )
    _assert_not_the_in_tree_config(merged, "CDK merge")


# ---------------------------------------------------------------------------
# The Terraform codepipeline-executor module, from its buildspec templates
# ---------------------------------------------------------------------------


def _terraform_buildspec(name: str) -> dict:
    """Render a buildspec as `templatefile` does, and point it at the repo's init."""
    text = (EXECUTOR / name).read_text(encoding="utf-8")
    placeholder = "${s3_sync_b64}"
    assert placeholder in text, f"{name} no longer embeds the S3 helper"
    rendered = text.replace(
        placeholder, base64.b64encode(TERRAFORM_S3_SYNC.read_bytes()).decode()
    )
    assert re.search(r"(?<!\$)\$\{", rendered) is None, (
        f"{name} has a template variable this does not fill"
    )
    # templatefile renders the escape $${ as a literal ${.
    rendered = rendered.replace("$${", "${")
    assert CONTAINER_INIT_PATH in rendered, f"{name} no longer runs ash-container-init"
    init = f"{shlex.quote(sys.executable)} {shlex.quote(str(CONTAINER_INIT))}"
    return yaml.safe_load(rendered.replace(CONTAINER_INIT_PATH, init))


def _terraform_environment(
    ash_env: dict[str, str], workdir: pathlib.Path, bucket: str, shard_count: int
) -> dict[str, str]:
    env = dict(ash_env)
    env.update(
        {
            # The module's defaults, and no base config.
            "ASH_BASE_CONFIG_SSM_PARAMETER": "",
            "ASH_OFFLINE": "NO",
            "RESULTS_PREFIX": "shard-results",
            "MIN_SEVERITY": "low",
            "FAIL_ON_FINDINGS": "true",
            "SHARD_COUNT": str(shard_count),
            "RESULTS_BUCKET": bucket,
            "PIPELINE_EXECUTION_ID": EXECUTION_ID,
            "TMPDIR": str(workdir / "tmp"),
        }
    )
    (workdir / "tmp").mkdir(parents=True, exist_ok=True)
    return env


def test_the_terraform_pipeline_reads_neither_shard_nor_merge_config_from_the_checkout(
    ash_env: dict[str, str], bucket: str, s3, tmp_path: pathlib.Path
):
    """Every shard records ASH's defaults, and the merge fails on the finding."""
    shard_spec = _terraform_buildspec("buildspec-shard.yml.tftpl")
    merge_spec = _terraform_buildspec("buildspec-merge.yml.tftpl")
    shard_count = 2

    def run_shard(index: int) -> None:
        workdir = tmp_path / f"tf-shard-{index}"
        source = _checkout(workdir / "src")
        env = _terraform_environment(ash_env, workdir, bucket, shard_count)
        env["SHARD_INDEX"] = str(index)
        env["CODEBUILD_SRC_DIR"] = str(source)
        env["CODEBUILD_BUILD_ARN"] = _build_arn(_build_id(f"tf-shard-{index}", index))
        for phase in ("pre_build", "build", "post_build"):
            _ok(
                _run_phase(phase_commands(shard_spec, phase), env, source),
                f"shard {index} {phase}",
            )

    with ThreadPoolExecutor(max_workers=shard_count) as pool:
        list(pool.map(run_shard, range(shard_count)))

    for index in range(shard_count):
        build = _build_arn(_build_id(f"tf-shard-{index}", index))
        key = f"shard-results/{EXECUTION_ID}/shard-{index}/{build}/ash_aggregated_results.json"
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        _assert_not_the_in_tree_config(json.loads(body), f"Terraform shard {index}")

    workdir = tmp_path / "tf-merge"
    source = _checkout(workdir / "src")
    env = _terraform_environment(ash_env, workdir, bucket, shard_count)
    env["CODEBUILD_SRC_DIR"] = str(source)
    env["CODEBUILD_INITIATOR"] = f"codepipeline/{PIPELINE}"
    env["CODEBUILD_BUILD_ARN"] = _build_arn(_build_id("tf-merge", 99))
    actions = _shard_actions("tf-shard", shard_count)
    with CodePipelineStub(PIPELINE, actions, page_size=10) as stub:
        env["AWS_ENDPOINT_URL_CODEPIPELINE"] = stub.url
        for phase in ("pre_build", "build"):
            _ok(
                _run_phase(phase_commands(merge_spec, phase), env, source),
                f"merge {phase}",
            )
    post_build = _run_phase(phase_commands(merge_spec, "post_build"), env, source)
    assert post_build.returncode == 2, (
        f"expected the merge verdict to be exit 2 for the finding, got "
        f"{post_build.returncode}: {post_build.stdout[-2000:]} {post_build.stderr[-2000:]}"
    )
    merged = json.loads(
        (source / "merged" / "ash_aggregated_results.json").read_text(encoding="utf-8")
    )
    _assert_not_the_in_tree_config(merged, "Terraform merge")
