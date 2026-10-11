#!/usr/bin/env python3
"""Minimal recursive S3 upload and download, using boto3.

Exists because the shard and merge actions run *inside the ASH image* rather than
a CodeBuild standard image. Running there is what puts `ash` directly on PATH,
with no Docker-in-Docker and no privileged build. The trade is that the ASH image
ships git, curl, and boto3 but not the AWS CLI, so `aws s3 cp --recursive` is not
available. boto3 is, because ASH declares it as a runtime dependency.

Usage:
    ash_s3_sync.py upload   <local-dir> <bucket> <key-prefix>
    ash_s3_sync.py download <bucket> <key-prefix> <local-dir>
    ash_s3_sync.py collect  <bucket> <key-prefix> <local-dir> <execution-id> <shard-count>

Both directions are recursive. Empty directories are not represented in S3 and
are therefore not recreated on download.
"""

from __future__ import annotations

import os
import pathlib
import sys

import boto3


def _fail(message: str) -> None:
    print(f"ash_s3_sync: {message}", file=sys.stderr)
    raise SystemExit(2)


def upload(local_dir: str, bucket: str, prefix: str) -> int:
    root = pathlib.Path(local_dir)
    if not root.is_dir():
        _fail(f"{local_dir} is not a directory")

    client = boto3.client("s3")
    prefix = prefix.strip("/")
    count = 0

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        key = f"{prefix}/{relative}" if prefix else relative
        client.upload_file(str(path), bucket, key)
        count += 1

    print(f"ash_s3_sync: uploaded {count} file(s) to s3://{bucket}/{prefix}/")
    return count


def download(bucket: str, prefix: str, local_dir: str) -> int:
    client = boto3.client("s3")
    prefix = prefix.strip("/")
    root = pathlib.Path(local_dir)
    root.mkdir(parents=True, exist_ok=True)

    paginator = client.get_paginator("list_objects_v2")
    count = 0

    for page in paginator.paginate(
        Bucket=bucket, Prefix=f"{prefix}/" if prefix else ""
    ):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if key.endswith("/"):
                continue
            relative = key[len(prefix) + 1 :] if prefix else key
            if not relative:
                continue

            # Every segment must be a plain name. S3 stores "." and ".." segments
            # literally, so such a key is its own object, yet on disk it names
            # another key's file or a path outside local_dir. S3 keys are written
            # by whoever can write the bucket.
            if any(part in ("", ".", "..") for part in relative.split("/")):
                _fail(
                    f"key {key!r} has an empty, '.' or '..' segment, so it would "
                    f"write outside {local_dir} or onto another key's file"
                )
            destination = root / relative

            # A link already under local_dir could still lead outside it.
            resolved = destination.resolve()
            if not resolved.is_relative_to(root.resolve()):
                _fail(f"key {key!r} would write outside {local_dir}")

            destination.parent.mkdir(parents=True, exist_ok=True)
            client.download_file(bucket, key, str(destination))
            count += 1

    print(f"ash_s3_sync: downloaded {count} file(s) from s3://{bucket}/{prefix}/")
    return count


def _calling_build() -> tuple[str, str, str]:
    """Partition, Region and account of this build, from CODEBUILD_BUILD_ARN."""
    parts = os.environ.get("CODEBUILD_BUILD_ARN", "").split(":")
    if len(parts) < 7 or parts[0] != "arn" or parts[2] != "codebuild":
        _fail("CODEBUILD_BUILD_ARN does not hold this build's ARN")
    return parts[1], parts[3], parts[4]


def _shard_builds(
    pipeline: str, execution_id: str, shard_count: int
) -> list[tuple[str, set[str]]]:
    """For each shard action, its one succeeded build and the builds of its other runs.

    CodePipeline lists every run of an action in an execution: a retried shard has a
    failed run and a succeeded one. The externalExecutionId of a CodeBuild action is its
    build id, <project>:<uuid>.
    """
    client = boto3.client("codepipeline")
    request = {
        "pipelineName": pipeline,
        "filter": {"pipelineExecutionId": execution_id},
    }
    details = []
    while True:
        page = client.list_action_executions(**request)
        details.extend(page.get("actionExecutionDetails", []))
        if not page.get("nextToken"):
            break
        request["nextToken"] = page["nextToken"]
    shards = []
    for index in range(shard_count):
        name = f"Shard{index}"
        runs = [
            d
            for d in details
            if d.get("actionName") == name
            and d.get("pipelineExecutionId") == execution_id
        ]
        builds = []
        for run in runs:
            project = (
                run.get("input", {}).get("configuration", {}).get("ProjectName", "")
            )
            build = (
                run.get("output", {})
                .get("executionResult", {})
                .get("externalExecutionId", "")
            )
            if not project or not build.startswith(project + ":"):
                _fail(
                    f"{name} reports build {build!r}, which is not a build of project {project!r}"
                )
            builds.append((run.get("status"), build))
        succeeded = [build for status, build in builds if status == "Succeeded"]
        if len(succeeded) != 1:
            _fail(
                f"expected one succeeded run of {name} in execution {execution_id}, "
                f"found {len(succeeded)}"
            )
        shards.append((succeeded[0], {build for _, build in builds} - set(succeeded)))
    return shards


def collect(
    bucket: str, prefix: str, local_dir: str, execution_id: str, shard_count: str
) -> int:
    """Download each shard's results from the build CodePipeline reports for it.

    Shard N writes under <prefix>/shard-N/<its build ARN>/, which its role allows only for
    its own build. This asks CodePipeline which build ran each shard action of this
    execution, downloads that build's keys to <local-dir>/shard-N/, skips the keys of the
    action's other runs, and refuses every other key: nothing but this execution's shard
    builds writes under <prefix>/, apart from the merge's own merged/ output.
    """
    initiator = os.environ.get("CODEBUILD_INITIATOR", "")
    if not initiator.startswith("codepipeline/"):
        _fail("CODEBUILD_INITIATOR does not name the pipeline that started this build")
    pipeline = initiator[len("codepipeline/") :]
    partition, region, account = _calling_build()
    prefix = prefix.strip("/")
    arn = f"arn:{partition}:codebuild:{region}:{account}:build/"
    shards = _shard_builds(pipeline, execution_id, int(shard_count))
    wanted = [
        f"{prefix}/shard-{i}/{arn}{build}/" for i, (build, _) in enumerate(shards)
    ]
    stale = [
        f"{prefix}/shard-{i}/{arn}{build}/"
        for i, (_, others) in enumerate(shards)
        for build in others
    ]
    client = boto3.client("s3")
    root = pathlib.Path(local_dir)
    root.mkdir(parents=True, exist_ok=True)
    count = 0

    for page in client.get_paginator("list_objects_v2").paginate(
        Bucket=bucket, Prefix=f"{prefix}/"
    ):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if key.endswith("/") or key.startswith(f"{prefix}/merged/"):
                continue
            if any(key.startswith(p) for p in stale):
                continue
            index = next((i for i, p in enumerate(wanted) if key.startswith(p)), None)
            if index is None:
                _fail(
                    f"key {key!r} is not under a build this execution lists for its shards"
                )
            relative = key[len(wanted[index]) :]
            if any(part in ("", ".", "..") for part in relative.split("/")):
                _fail(
                    f"key {key!r} has an empty, '.' or '..' segment, so it would "
                    f"write outside {local_dir} or onto another key's file"
                )
            destination = root / f"shard-{index}" / relative
            if not destination.resolve().is_relative_to(root.resolve()):
                _fail(f"key {key!r} would write outside {local_dir}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            client.download_file(bucket, key, str(destination))
            count += 1

    print(
        f"ash_s3_sync: collected {count} file(s) from {len(wanted)} shard build(s) of execution {execution_id}"
    )
    return count


def main(argv: list[str]) -> int:
    if not argv:
        _fail("expected a subcommand: upload or download")

    action, rest = argv[0], argv[1:]

    if action == "upload":
        if len(rest) != 3:
            _fail("upload takes <local-dir> <bucket> <key-prefix>")
        upload(rest[0], rest[1], rest[2])
    elif action == "download":
        if len(rest) != 3:
            _fail("download takes <bucket> <key-prefix> <local-dir>")
        download(rest[0], rest[1], rest[2])
    elif action == "collect":
        if len(rest) != 5:
            _fail(
                "collect takes <bucket> <key-prefix> <local-dir> <execution-id> <shard-count>"
            )
        collect(*rest)
    else:
        _fail(f"unknown subcommand {action!r}; expected upload, download or collect")

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
