"""No image this component builds is ever pushed to a registry.

ASH publishes no container image, and the operator's images follow suit: the e2e
builds them locally and hands them to kind with ``kind load docker-image``. A push
added to the workflow or the harness later would put an image that scans source
code into a public registry, so the absence is asserted rather than assumed.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

OPERATOR_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = OPERATOR_DIR.parents[1]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ash-kubernetes-operator.yml"

# Anything that logs in to a registry, pushes an image, or uses an action whose job
# is publishing one.
PUBLISH = re.compile(
    r"docker\s+(?:image\s+)?push"
    r"|[\"']docker[\"']\s*,\s*(?:[\"']image[\"']\s*,\s*)?[\"']push[\"']"
    r"|[\"']docker[\"']\s*,\s*[\"']login[\"']"
    r"|docker\s+login"
    r"|\bpush:\s*true"
    r"|docker/login-action"
    r"|docker/build-push-action"
    r"|aws-actions/amazon-ecr-login"
    r"|\bcrane\s+push|\bskopeo\s+copy|\bpodman\s+push|\bbuildah\s+push"
)


def checked_files() -> list[Path]:
    files = [WORKFLOW]
    files += sorted((OPERATOR_DIR / "tests" / "e2e").rglob("*.py"))
    files += sorted((OPERATOR_DIR / "tests" / "e2e").glob("Dockerfile*"))
    files += [OPERATOR_DIR / "Dockerfile"]
    return files


def find_publishing(paths: list[Path]) -> list[str]:
    hits = []
    for path in paths:
        for number, line in enumerate(path.read_text().splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            if PUBLISH.search(line):
                hits.append(f"{path}:{number}: {line.strip()}")
    return hits


def test_the_files_under_check_exist():
    # A renamed workflow would make the scan below pass over nothing.
    missing = [str(path) for path in checked_files() if not path.is_file()]
    assert not missing, missing


def test_nothing_pushes_or_logs_in_to_a_registry():
    hits = find_publishing(checked_files())
    assert not hits, "an image would leave the runner:\n" + "\n".join(hits)


def test_the_e2e_loads_images_into_kind_instead():
    conftest = (OPERATOR_DIR / "tests" / "e2e" / "conftest.py").read_text()
    assert '"kind", "load", "docker-image"' in conftest


@pytest.mark.parametrize(
    "line",
    [
        "        run: docker push ghcr.io/example/ash-operator:latest",
        "          push: true",
        "      - uses: docker/login-action@0123456789abcdef0123456789abcdef01234567 # v3",
        '    run(["docker", "push", OPERATOR_IMAGE])',
        '    run(["docker", "image", "push", ASH_IMAGE])',
        "    run(['docker', 'login', 'ghcr.io'])",
    ],
)
def test_the_pattern_catches_a_push(tmp_path, line):
    # Positive control: without it the guard above could be a regex matching nothing.
    planted = tmp_path / "planted.yml"
    planted.write_text(line + "\n")
    assert find_publishing([planted])
