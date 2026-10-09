# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A sandboxed online trivy-repo scan of a tree with a jar matches the unsandboxed one.

The sandbox mounts trivy's cache read-only and ASH updates trivy's vulnerability
database outside it first (utils/content_db_refresh.py). The Java database is not
updated: ``trivy repository`` does not analyze JAR, WAR or EAR files and never reads
it (measured with trivy 0.75), and it is about 935 MiB. This pins both halves: with
a stale Java database in the cache, a tree holding a jar and a pom.xml gives the
same findings sandboxed and unsandboxed, and neither run touches the Java database.

Needs trivy and a network (the first run downloads trivy's vulnerability database
into a cache of its own). Skipped where trivy is not installed, and per backend where that
backend does not work.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from automated_security_helper.utils.sandbox import clear_backend_cache, resolve_backend
from automated_security_helper.utils.sandbox.scope import SandboxUnavailable
from automated_security_helper.utils.subprocess_utils import find_executable

pytestmark = pytest.mark.integration

POM = """<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>example</groupId>
  <artifactId>fixture</artifactId>
  <version>1</version>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.14.1</version>
    </dependency>
  </dependencies>
</project>
"""


def _require(backend: str) -> None:
    clear_backend_cache()
    try:
        resolve_backend(backend)
    except SandboxUnavailable as e:
        pytest.skip(f"{backend} unavailable: {e}")


def _fixture_repo(root: Path) -> Path:
    repo = root / "repo"
    (repo / "lib").mkdir(parents=True)
    (repo / "pom.xml").write_text(POM)
    with zipfile.ZipFile(repo / "lib" / "log4j-core-2.14.1.jar", "w") as jar:
        jar.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
        jar.writestr(
            "META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties",
            "groupId=org.apache.logging.log4j\nartifactId=log4j-core\nversion=2.14.1\n",
        )
    git = [
        "git",
        "-C",
        str(repo),
        "-c",
        "user.name=t",
        "-c",
        "user.email=t@example.invalid",
    ]
    subprocess.run(["git", "init", "-q", str(repo)], check=True)  # nosec B603, B607 - fixed argv
    subprocess.run([*git, "add", "-A"], check=True)  # nosec B603 - fixed argv
    subprocess.run([*git, "commit", "-qm", "fixture"], check=True)  # nosec B603 - fixed argv
    return repo


def _stale_java_db(cache: Path) -> dict:
    """A Java database trivy would replace if it read it: NextUpdate long past."""
    java = cache / "java-db"
    java.mkdir(parents=True)
    (java / "metadata.json").write_text(
        json.dumps(
            {
                "Version": 1,
                "NextUpdate": "2026-01-02T00:00:00Z",
                "UpdatedAt": "2026-01-01T00:00:00Z",
                "DownloadedAt": "2026-01-01T01:00:00Z",
            }
        )
    )
    (java / "trivy-java.db").write_bytes(b"")
    return _listing(java)


def _listing(directory: Path) -> dict:
    return {
        p.relative_to(directory).as_posix(): (p.stat().st_mtime_ns, p.read_bytes())
        for p in sorted(directory.rglob("*"))
        if p.is_file()
    }


def _scan(repo: Path, output: Path, mode: str, env: dict) -> set:
    ash = Path(sys.executable).with_name("ash")
    result = subprocess.run(  # nosec B603 - fixed argv
        [
            str(ash if ash.exists() else shutil.which("ash")),
            "scan",
            "--source-dir",
            str(repo),
            "--output-dir",
            str(output),
            "--scanners",
            "trivy-repo",
            "--sandbox",
            mode,
            "--no-progress",
            "--fail-on-findings",
            "false",
            "--config-overrides",
            "ash_plugin_modules=[automated_security_helper.plugin_modules.ash_trivy_plugins]",
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=900,
        check=False,
    )
    document = json.loads((output / "ash_aggregated_results.json").read_text())
    row = document["scanner_results"].get("trivy-repo") or {}
    assert row.get("status") == "FAILED", (
        f"trivy-repo under --sandbox {mode}: {row}\n{(result.stdout + result.stderr)[-4000:]}"
    )
    found = set()
    for run in document["sarif"]["runs"]:
        for item in run.get("results") or []:
            if (item.get("properties") or {}).get("scanner_name") != "trivy-repo":
                continue
            location = ((item.get("locations") or [{}])[0] or {}).get(
                "physicalLocation"
            ) or {}
            found.add(
                (
                    str(item.get("ruleId")),
                    (location.get("artifactLocation") or {}).get("uri"),
                )
            )
    return found


@pytest.mark.parametrize("backend", ["bwrap", "firejail", "landlock"])
def test_a_jar_and_a_stale_java_database_change_nothing_in_the_sandbox(
    tmp_path, backend
):
    if not find_executable("trivy"):
        pytest.skip("trivy is not installed")
    _require(backend)
    repo = _fixture_repo(tmp_path)
    cache = tmp_path / "trivy-cache"
    java_before = _stale_java_db(cache)
    env = {
        **os.environ,
        "TRIVY_CACHE_DIR": str(cache),
        "HOME": os.environ.get("HOME", str(tmp_path)),
    }
    env.pop("ASH_OFFLINE", None)

    # Sandboxed first: it is the run that has to get trivy's database prepared.
    boxed = _scan(repo, tmp_path / "out-boxed", backend, env)
    unboxed = _scan(repo, tmp_path / "out-off", "off", env)

    assert boxed == unboxed, (
        f"only unsandboxed: {unboxed - boxed}; only sandboxed: {boxed - unboxed}"
    )
    assert any("CVE-2021-44228" in rule for rule, _ in boxed), boxed
    # Neither run read, replaced or added to the Java database.
    assert _listing(cache / "java-db") == java_before
