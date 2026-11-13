# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The nix shell downloads grype's and trivy's databases with no config of the repo's.

Why this file exists
--------------------
flake.nix's shellHook runs wherever `nix develop` was started. grype looks for
`.grype.yaml` and `.grype/config.yaml` in its working directory and trivy for
`trivy.yaml`, so the downloads live in nix/refresh-content-dbs.sh, which runs them
from an empty directory of its own with an explicit empty config. These tests run
that script with stand-in tools from a directory holding both configs, each naming a
database source that does not exist, and check neither tool could have read them.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "nix" / "refresh-content-dbs.sh"
FLAKE = REPO_ROOT / "flake.nix"

pytestmark = pytest.mark.skipif(os.name == "nt", reason="the script is POSIX sh")

_FAKE_TOOL = """#!{python}
import json, os, sys
record = {{"tool": os.path.basename(sys.argv[0]), "argv": sys.argv[1:], "cwd": os.getcwd()}}
for name in ("-c", "--config"):
    if name in sys.argv:
        path = sys.argv[sys.argv.index(name) + 1]
        record["config"] = path
        record["config_text"] = open(path).read() if os.path.isfile(path) else None
with open({log!r}, "a", encoding="utf-8") as handle:
    handle.write(json.dumps(record) + "\\n")
"""


def _repo_with_bogus_sources(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / ".grype").mkdir(parents=True)
    (repo / ".git").mkdir()
    (repo / ".grype.yaml").write_text(
        'db:\n  update-url: "https://bogus-grype.invalid/listing.json"\n'
    )
    (repo / ".grype" / "config.yaml").write_text(
        'db:\n  update-url: "https://bogus-grype.invalid/listing.json"\n'
    )
    (repo / "trivy.yaml").write_text("db:\n  repository: bogus-trivy.invalid/db\n")
    return repo


def _run(tmp_path: Path) -> list:
    repo = _repo_with_bogus_sources(tmp_path)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "calls.jsonl"
    for tool in ("grype", "trivy"):
        fake = bin_dir / tool
        fake.write_text(_FAKE_TOOL.format(python=sys.executable, log=str(log)))
        fake.chmod(0o755)
    env = {
        **os.environ,
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "GRYPE_DB_CACHE_DIR": str(tmp_path / "grype-cache"),
        "TRIVY_CACHE_DIR": str(tmp_path / "trivy-cache"),
        "TMPDIR": str(tmp_path / "tmp"),
    }
    (tmp_path / "tmp").mkdir()
    result = subprocess.run(  # nosec B603 B607 - fixed script, stand-in tools
        ["sh", str(SCRIPT)],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    calls = [json.loads(line) for line in log.read_text().splitlines()]
    return [{**c, "repo": str(repo)} for c in calls]


@pytest.mark.integration
@pytest.mark.parametrize("tool", ["grype", "trivy"])
def test_the_download_reads_no_config_from_the_repository(tmp_path, tool):
    calls = [c for c in _run(tmp_path) if c["tool"] == tool]
    assert calls, f"{tool} was not run"  # not vacuous
    for call in calls:
        cwd = Path(call["cwd"]).resolve()
        assert not cwd.is_relative_to(Path(call["repo"]).resolve()), call
        assert not (cwd / "trivy.yaml").exists() and not (cwd / ".grype.yaml").exists()
        assert call.get("config") is not None, f"{tool} got no explicit config: {call}"
        assert call["config_text"] == "", call
        assert (
            not Path(call["config"])
            .resolve()
            .is_relative_to(Path(call["repo"]).resolve())
        )


@pytest.mark.integration
def test_the_downloads_keep_their_cache_and_subcommand(tmp_path):
    calls = {c["tool"]: c for c in _run(tmp_path)}
    assert calls["grype"]["argv"][:2] == ["db", "update"]
    trivy = calls["trivy"]["argv"]
    assert trivy[:2] == ["image", "--download-db-only"]
    assert trivy[trivy.index("--cache-dir") + 1] == str(tmp_path / "trivy-cache")


@pytest.mark.unit
def test_the_shell_hook_downloads_only_through_the_script():
    text = FLAKE.read_text(encoding="utf-8")
    assert "${self}/nix/refresh-content-dbs.sh" in text
    hook = text[text.index("shellHook = ''") :]
    hook = hook[: hook.index("'';")]
    bare = [
        line.strip()
        for line in hook.splitlines()
        if re.search(r"\bgrype db update\b|\btrivy image --download-db-only\b", line)
        and not line.strip().startswith("#")
    ]
    assert bare == [], f"the shell hook downloads a database itself: {bare}"
