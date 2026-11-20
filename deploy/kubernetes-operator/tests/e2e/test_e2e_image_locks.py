"""The two images refuse a dependency whose hash is not the locked one.

The session builds both images from their hashed requirement files, which is the
positive half: a build that succeeds installed only what those files pin. This is the
negative half. Each image is built again from a copy of its context in which one
sha256 in one requirement file is changed, and the build must stop at pip with its
hash-mismatch error. A Dockerfile that dropped --require-hashes, or installed the
package from somewhere other than that file, would build here and fail the test.

Nothing is tagged and nothing leaves the host. The builds run after the session's own
(the fixtures depend on the built images), so every layer before the pip step is
cached and each build fails within seconds of reaching it.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from tests.e2e.helpers import (
    E2E_DIR,
    OPERATOR_DIR,
    stage_ash_locks,
    stage_ash_source,
)

pytestmark = pytest.mark.e2e

HASH = re.compile(r"--hash=sha256:([0-9a-f]{64})")
MISMATCH = "THESE PACKAGES DO NOT MATCH THE HASHES FROM THE REQUIREMENTS FILE"


def tamper(lock: Path, package: str) -> str:
    """Flip one hex digit of every hash of *package* in *lock*; return the package line."""
    lines = lock.read_text().splitlines(keepends=True)
    start = next(i for i, line in enumerate(lines) if line.startswith(f"{package}=="))
    changed = 0
    for i in range(start, len(lines)):
        if i > start and not lines[i].startswith(" "):
            break
        match = HASH.search(lines[i])
        if match:
            digest = match.group(1)
            flipped = ("0" if digest[0] != "0" else "1") + digest[1:]
            lines[i] = lines[i].replace(digest, flipped)
            changed += 1
    assert changed, f"no hash under {package} in {lock}"
    lock.write_text("".join(lines))
    return lines[start].strip()


def build(context: Path, dockerfile: Path) -> subprocess.CompletedProcess[str]:
    argv = ["docker", "build", "--progress=plain", "-f", str(dockerfile), str(context)]
    print(f"$ {' '.join(argv)}", flush=True)
    return subprocess.run(argv, capture_output=True, text=True, timeout=1800, check=False)


@pytest.fixture(scope="module")
def tampered_operator_build(operator_image):
    with tempfile.TemporaryDirectory(prefix="ash-op-tampered-") as scratch:
        context = Path(scratch)
        for name in (
            "Dockerfile",
            "pyproject.toml",
            "README.md",
            "requirements.txt",
            "build-requirements.txt",
        ):
            shutil.copy(OPERATOR_DIR / name, context / name)
        shutil.copytree(OPERATOR_DIR / "ash_operator", context / "ash_operator")
        line = tamper(context / "requirements.txt", "kopf")
        return {"line": line, "result": build(context, context / "Dockerfile")}


@pytest.fixture(scope="module")
def tampered_ash_build(ash_image):
    with tempfile.TemporaryDirectory(prefix="ash-e2e-tampered-") as scratch:
        context = Path(scratch)
        shutil.copy(E2E_DIR / "Dockerfile.ash", context / "Dockerfile")
        stage_ash_source(context / "ash-source")
        stage_ash_locks(context / "locks")
        line = tamper(context / "locks" / "scanner-requirements.txt", "bandit")
        return {"line": line, "result": build(context, context / "Dockerfile")}


@pytest.mark.negative_control
class TestATamperedLockIsRefused:
    @pytest.mark.parametrize("which", ["operator", "ash"])
    def test_the_build_stops_at_the_hash_check(self, which, request):
        built = request.getfixturevalue(f"tampered_{which}_build")
        result = built["result"]
        output = result.stdout + result.stderr
        assert result.returncode != 0, f"the {which} image built with {built['line']} tampered"
        assert MISMATCH in output, output[-3000:]
        name = built["line"].split("==")[0]
        assert re.search(rf"^.*\b{re.escape(name)}==", output, re.MULTILINE), output[-3000:]
