#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The Terraform pipeline's shards and merge spell ASH's commands the way its ASH does.

Why this exists
---------------
The shard and merge actions run inside the ASH image the module builds from
``ash_version``. ASH 3.9 scans a directory with ``ash scan fs PATH`` and merges with
``ash results merge``; the older spellings, ``ash scan --source-dir PATH`` and
``ash merge``, still run there but print a deprecation line, and they go in ASH v4.0.
An ``ash_version`` older than 3.9 (the module's default, until the release commit
moves it) has only the older spellings. So each command asks the image's ASH first,
and only an ASH with the new spelling prints it in that help.

These run the committed build commands with a stand-in ``ash`` that answers the help
probes as each kind of release and records every other call, and a stand-in
``ash-container-init`` that only runs what it is given.
test_deploy_pipeline_config_source.py runs the same commands with this tree's real
ASH, which takes the new spelling.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from tests.unit.deploy.gate_probe_answers import (
    FS_HELP,
    RELEASE_WITH_SUBJECT,
    RELEASE_WITHOUT_SUBJECT,
    SUBJECTLESS_HELP,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
MODULE = REPO_ROOT / "deploy" / "terraform" / "modules" / "codepipeline-executor"
CONTAINER_INIT_PATH = "/usr/local/bin/ash-container-init"

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        os.name == "nt",
        reason="executes a POSIX buildspec command destined for a Linux build container",
    ),
]

#: The stand-in ``ash``. Probes are answered as RELEASE and not recorded; every other
#: call is recorded, one JSON argv per line, and exits 0.
_FAKE_ASH = """import json, sys
argv = sys.argv[1:]
RELEASE = {release}
if argv[:3] == ["scan", "fs", "--help"] or argv[:2] == ["scan", "--help"]:
    sys.stdout.write({fs_help} if RELEASE == {with_subject} else {subjectless_help})
    sys.exit(0)
if argv[:3] == ["results", "merge", "--help"]:
    if RELEASE == {with_subject}:
        print("Usage: ash results merge [OPTIONS]")
        sys.exit(0)
    print("Error: No such command 'results'.", file=sys.stderr)
    sys.exit(2)
with open({record}, "a", encoding="utf-8") as handle:
    handle.write(json.dumps(argv) + "\\n")
"""


def _build_command(name: str, marker: str) -> str:
    """The one build-phase command of buildspec *name* that contains *marker*."""
    spec = yaml.safe_load((MODULE / name).read_text(encoding="utf-8"))
    matches = [c for c in spec["phases"]["build"]["commands"] if marker in c]
    assert len(matches) == 1, f"expected one build command with {marker!r} in {name}"
    assert CONTAINER_INIT_PATH in matches[0], (
        f"{name} no longer runs ash-container-init"
    )
    return matches[0]


def _run(
    tmp_path: Path, command: str, release: str, env: dict[str, str]
) -> list[list[str]]:
    """Run *command* against the stand-ins, answering as *release*; return the calls."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    record = tmp_path / "ash.jsonl"
    ash = bin_dir / "ash"
    ash.write_text(
        f"#!{sys.executable} -I\n"
        + _FAKE_ASH.format(
            release=json.dumps(release),
            with_subject=json.dumps(RELEASE_WITH_SUBJECT),
            fs_help=json.dumps(FS_HELP),
            subjectless_help=json.dumps(SUBJECTLESS_HELP),
            record=json.dumps(str(record)),
        ),
        encoding="utf-8",
    )
    ash.chmod(0o755)
    init = bin_dir / "ash-container-init"
    init.write_text('#!/bin/sh\nexec "$@"\n', encoding="utf-8")
    init.chmod(0o755)
    shell = shutil.which("sh")
    assert shell, "no sh on PATH"

    work = tmp_path / "work"
    work.mkdir()
    subprocess.run(
        [shell, "-c", command.replace(CONTAINER_INIT_PATH, str(init))],
        cwd=work,
        env={
            "PATH": f"{bin_dir}{os.pathsep}/usr/bin{os.pathsep}/bin",
            "TMPDIR": str(tmp_path),
            "ASH_BASE_CONFIG_SSM_PARAMETER": "",
            **env,
        },
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    if not record.exists():
        return []
    return [
        json.loads(line) for line in record.read_text(encoding="utf-8").splitlines()
    ]


@pytest.mark.parametrize(
    "release, prefix",
    [
        (RELEASE_WITH_SUBJECT, ["scan", "fs", "."]),
        (RELEASE_WITHOUT_SUBJECT, ["scan", "--source-dir", "."]),
    ],
    ids=["with-subject", "without-subject"],
)
def test_a_shard_scans_the_checkout_the_way_its_ash_names_a_directory(
    tmp_path, release, prefix
):
    command = _build_command("buildspec-shard.yml.tftpl", "--shard-index")

    calls = _run(tmp_path, command, release, {"SHARD_INDEX": "1", "SHARD_COUNT": "3"})

    # One call: the probe is answered, not recorded.
    assert len(calls) == 1, calls
    argv = calls[0]
    assert argv[:3] == prefix, argv
    if release == RELEASE_WITH_SUBJECT:
        assert "--source-dir" not in argv, argv
    for pair in (["--shard-index", "1"], ["--shard-count", "3"]):
        start = argv.index(pair[0])
        assert argv[start : start + 2] == pair, argv
    assert "--no-fail-on-findings" in argv, argv


@pytest.mark.parametrize(
    "release, prefix",
    [
        (RELEASE_WITH_SUBJECT, ["results", "merge"]),
        (RELEASE_WITHOUT_SUBJECT, ["merge"]),
    ],
    ids=["with-subject", "without-subject"],
)
def test_the_merge_runs_the_merge_its_ash_has(tmp_path, release, prefix):
    command = _build_command("buildspec-merge.yml.tftpl", "MERGE_EXIT=$?")

    calls = _run(
        tmp_path,
        command,
        release,
        {"SHARD_COUNT": "3", "MIN_SEVERITY": "low", "FAIL_ON_FINDINGS": "true"},
    )

    assert len(calls) == 1, calls
    argv = calls[0]
    assert argv[: len(prefix)] == prefix, argv
    assert argv[argv.index("--min-severity") + 1] == "low", argv
    assert "--fail-on-findings" in argv, argv
    results = [argv[i + 1] for i, word in enumerate(argv) if word == "--results"]
    assert results == [f"shard-results/shard-{i}" for i in range(3)], argv
