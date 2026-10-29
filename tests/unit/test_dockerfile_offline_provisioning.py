# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An ``OFFLINE=YES`` image build fails when a content database or ruleset download fails.

Why this file exists
--------------------
The trivy step used to read::

    set -ue; ...; if [ "${OFFLINE}" = "YES" ]; then
        with-retry "trivy image --download-db-only ..." &&
        chmod -R 777 "${TRIVY_CACHE_DIR}" &&
        if [ -z "$(ls -A "${TRIVY_CACHE_DIR}/db")" ]; then ...; exit 1; fi;
        echo "offline provisioning verified: trivy database present"; fi

``set -e`` does not apply to a command in an AND-OR list other than the last one
(POSIX, ``set -e``; dash and bash both follow it). So when the download failed, the
chain stopped before the emptiness check, the shell carried on to the ``echo``, and
the step printed "verified" and exited 0: an offline image with no trivy database,
whose scans then fail with trivy MISSING. The grype and ruleset step had the same
shape one level down: its ``for`` loop over the semgrep rulesets sat inside an
``&&`` chain, so ``set -e`` was off for the loop body and a ruleset that failed to
download, other than the last one, was skipped without a word.

What these tests do
-------------------
Each RUN step is taken from the Dockerfile as text, the same way
``test_dockerfile_posix_shell.py`` reads it, and run under ``sh -c`` (dash where it is
installed, as in the image, and bash) with stand-in ``trivy``, ``grype`` and ``curl``
commands that fail on request. No image is built and no container runs. The real
``with-retry`` wraps the stand-ins, limited to one attempt. Each failing case has a
passing twin, so a harness that never reached the download cannot pass them.

The static check below covers the class rather than the two instances: a RUN that
turns on ``set -e`` uses ``;`` between commands, never ``&&``, because under ``set -e``
``a && b`` is ``a; b`` with the failure check removed from ``a``.
"""

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = REPO_ROOT / "Dockerfile"
WITH_RETRY = REPO_ROOT / "automated_security_helper" / "assets" / "with-retry.sh"

pytestmark = pytest.mark.skipif(os.name == "nt", reason="RUN steps are POSIX sh")

SHELLS = [name for name in ("dash", "bash") if shutil.which(name)]


def run_instructions(path: Path):
    """Yield ``(line_number, command)`` per RUN, continuations folded in.

    The same folding as ``test_dockerfile_posix_shell.run_instructions``.
    """
    lines = path.read_text(encoding="utf-8").splitlines()
    index = 0
    while index < len(lines):
        stripped = lines[index].strip()
        if re.match(r"^RUN\s", stripped):
            start = index + 1
            parts = [stripped]
            while parts[-1].rstrip().endswith("\\") and index + 1 < len(lines):
                index += 1
                parts.append(lines[index].strip())
            joined = " ".join(p.rstrip().rstrip("\\").strip() for p in parts)
            yield start, joined[len("RUN ") :]
        index += 1


def _step(marker: str) -> str:
    found = [cmd for _, cmd in run_instructions(DOCKERFILE) if marker in cmd]
    assert len(found) == 1, f"expected one RUN containing {marker!r}, found {found}"
    return found[0]


_TRIVY = """#!/bin/sh
case "${STUB_TRIVY:?}" in
  fail) echo "stub trivy: download failed" >&2; exit 1 ;;
  empty) exit 0 ;;
esac
cache=""
while [ $# -gt 0 ]; do
  if [ "$1" = "--cache-dir" ]; then cache="$2"; fi
  shift
done
mkdir -p "$cache/db" && echo db > "$cache/db/trivy.db"
"""

_GRYPE = """#!/bin/sh
if [ "${STUB_GRYPE:-ok}" = fail ]; then echo "stub grype: update failed" >&2; exit 1; fi
mkdir -p "$GRYPE_DB_CACHE_DIR/6" && echo db > "$GRYPE_DB_CACHE_DIR/6/vulnerability.db"
"""

_CURL = """#!/bin/sh
url=""; out=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift ;;
    https://*) url="$1" ;;
  esac
  shift
done
for bad in ${STUB_CURL_FAIL:-}; do
  case "$url" in */"$bad") echo "stub curl: 404 for $url" >&2; exit 22 ;; esac
done
printf 'rules: []\\n' > "$out"
"""


@pytest.fixture
def stub_env(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, text in (("trivy", _TRIVY), ("grype", _GRYPE), ("curl", _CURL)):
        (bin_dir / name).write_text(text, encoding="utf-8")
        (bin_dir / name).chmod(0o755)
    shutil.copy(WITH_RETRY, bin_dir / "with-retry")
    (bin_dir / "with-retry").chmod(0o755)
    return {
        **os.environ,
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "OFFLINE": "YES",
        "WITH_RETRY_MAX_ATTEMPTS": "1",
        "WITH_RETRY_DELAY": "0",
        "TRIVY_CACHE_DIR": str(tmp_path / "trivy"),
        "GRYPE_DB_CACHE_DIR": str(tmp_path / "grype"),
        "SEMGREP_RULES_CACHE_DIR": str(tmp_path / "semgrep"),
        "OPENGREP_RULES_CACHE_DIR": str(tmp_path / "opengrep"),
        "OFFLINE_SEMGREP_RULESETS": "p/ci p/secrets",
    }


def _run(
    shell: str, command: str, env: dict, **overrides
) -> subprocess.CompletedProcess:
    return subprocess.run(  # nosec B603 - a Dockerfile step against stand-in tools
        [shell, "-c", command],
        env={**env, **overrides},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


@pytest.mark.integration
@pytest.mark.parametrize("shell", SHELLS)
class TestTrivyStep:
    STEP = "--download-db-only"

    def test_a_failed_download_fails_the_step(self, shell, stub_env):
        result = _run(shell, _step(self.STEP), stub_env, STUB_TRIVY="fail")
        assert result.returncode != 0, (
            "the trivy download failed and the step still exited 0:\n" + result.stdout
        )
        assert "verified" not in result.stdout

    def test_a_download_that_leaves_no_database_fails_the_step(self, shell, stub_env):
        result = _run(shell, _step(self.STEP), stub_env, STUB_TRIVY="empty")
        assert result.returncode != 0
        assert "verified" not in result.stdout

    def test_a_download_that_lands_passes(self, shell, stub_env):
        """The control: the same harness passes when the database arrives."""
        result = _run(shell, _step(self.STEP), stub_env, STUB_TRIVY="ok")
        assert result.returncode == 0, result.stderr
        assert "offline provisioning verified: trivy database present" in result.stdout
        assert Path(stub_env["TRIVY_CACHE_DIR"], "db", "trivy.db").is_file()

    def test_an_online_build_downloads_nothing(self, shell, stub_env):
        result = _run(
            shell, _step(self.STEP), stub_env, OFFLINE="NO", STUB_TRIVY="fail"
        )
        assert result.returncode == 0, result.stderr
        assert Path(stub_env["TRIVY_CACHE_DIR"]).is_dir()

    def test_a_cache_directory_that_cannot_be_made_fails_the_step(
        self, shell, stub_env, tmp_path
    ):
        """``mkdir && chmod;`` hid a failed mkdir in an online build too."""
        blocker = tmp_path / "a-file"
        blocker.write_text("not a directory", encoding="utf-8")
        result = _run(
            shell,
            _step(self.STEP),
            stub_env,
            OFFLINE="NO",
            TRIVY_CACHE_DIR=str(blocker / "trivy"),
        )
        assert result.returncode != 0


@pytest.mark.integration
@pytest.mark.parametrize("shell", SHELLS)
class TestGrypeAndRulesetStep:
    STEP = "grype db update"

    def test_a_failed_grype_update_fails_the_step(self, shell, stub_env):
        result = _run(shell, _step(self.STEP), stub_env, STUB_GRYPE="fail")
        assert result.returncode != 0

    @pytest.mark.parametrize("failing", ["ci", "secrets"])
    def test_any_failed_ruleset_download_fails_the_step(self, shell, stub_env, failing):
        """Before the fix only the LAST ruleset's failure reached the exit status."""
        result = _run(shell, _step(self.STEP), stub_env, STUB_CURL_FAIL=failing)
        assert result.returncode != 0, (
            f"the {failing} ruleset failed to download and the step exited 0"
        )

    def test_every_download_landing_passes(self, shell, stub_env):
        """The control: both rulesets land in both caches, with the fetch time."""
        result = _run(shell, _step(self.STEP), stub_env)
        assert result.returncode == 0, result.stderr
        for cache in ("SEMGREP_RULES_CACHE_DIR", "OPENGREP_RULES_CACHE_DIR"):
            names = sorted(p.name for p in Path(stub_env[cache]).iterdir())
            assert names == [".ash-rules-fetched-at", "ci.yml", "secrets.yml"]


_QUOTED = re.compile(r"'[^']*'" + r'|"(?:[^"\\]|\\.)*"')


def _unquoted(command: str) -> str:
    """``command`` with single- and double-quoted strings removed.

    Crude, and enough here: an ``&&`` inside a quoted ``with-retry`` argument runs in
    a shell of its own and is not this RUN's chain.
    """
    return _QUOTED.sub("''", command)


_SET_E = re.compile(r"^\s*set\s+-[A-Za-z]*e")


def _and_chains_under_set_e(path: Path) -> list:
    return [
        (line, command)
        for line, command in run_instructions(path)
        if _SET_E.match(command) and "&&" in _unquoted(command)
    ]


@pytest.mark.unit
def test_no_run_under_set_e_chains_commands_with_and():
    offenders = _and_chains_under_set_e(DOCKERFILE)
    header = (
        "These RUN steps turn on set -e and join commands with '&&'. set -e skips "
        "every command of an AND-OR list but the last, so a failure there is "
        "ignored; use ';' between commands and 'if' for a real condition:"
    )
    assert not offenders, "\n".join(
        [header] + [f"  line {line}: {command[:160]}" for line, command in offenders]
    )


@pytest.mark.unit
def test_the_set_e_check_fires_on_the_old_trivy_step(tmp_path):
    """The control for the check above: the step as it was must trip it."""
    old = tmp_path / "Dockerfile"
    old.write_text(
        'RUN set -ue; mkdir -p "${D}"; \\\n'
        '    if [ "${OFFLINE}" = "YES" ]; then \\\n'
        '        with-retry "trivy image --download-db-only" && \\\n'
        '        chmod -R 777 "${D}"; \\\n'
        '        echo "verified"; \\\n'
        "    fi\n"
        "RUN with-retry 'corepack enable && corepack prepare pnpm@latest'\n"
        "RUN set -ue; with-retry 'a && b'; echo \"x && y\"\n",
        encoding="utf-8",
    )
    assert [line for line, _ in _and_chains_under_set_e(old)] == [1]


@pytest.mark.unit
def test_the_shells_under_test_include_one():
    assert SHELLS, "neither dash nor bash is installed, so nothing above ran"
