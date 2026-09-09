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

Both directions are recursive. Empty directories are not represented in S3 and
are therefore not recreated on download.
"""

from __future__ import annotations

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

    for page in paginator.paginate(Bucket=bucket, Prefix=f"{prefix}/" if prefix else ""):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if key.endswith("/"):
                continue
            relative = key[len(prefix) + 1 :] if prefix else key
            if not relative:
                continue
            destination = root / relative

            # Refuse a key that would escape the destination directory. S3 keys
            # are attacker-influenced in the general case, and a key containing
            # ".." would otherwise write outside local_dir.
            resolved = destination.resolve()
            if not resolved.is_relative_to(root.resolve()):
                _fail(f"key {key!r} would write outside {local_dir}")

            destination.parent.mkdir(parents=True, exist_ok=True)
            client.download_file(bucket, key, str(destination))
            count += 1

    print(f"ash_s3_sync: downloaded {count} file(s) from s3://{bucket}/{prefix}/")
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
    else:
        _fail(f"unknown subcommand {action!r}; expected upload or download")

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
