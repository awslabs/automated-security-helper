"""Every Dockerfile with a digest-pinned base image is watched by a Dependabot docker entry.

A digest pin never moves on its own: nothing proposes the next digest unless a docker
entry in .github/dependabot.yml lists the Dockerfile's directory, and `directory` is not
recursive. The operator's two images sat outside every entry while the root one was
covered, so their python:3.12-slim digest could only age. This census reads the tracked
tree, the same way .github/scripts/assert-images-pinned.py finds Dockerfiles, and fails
on a pinned one whose directory no docker entry names.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
DEPENDABOT = REPO_ROOT / ".github" / "dependabot.yml"
DOCKERFILE_NAME = re.compile(r"^(Dockerfile.*|.*\.Dockerfile|Containerfile.*)$")
PINNED_FROM = re.compile(
    r"^\s*FROM\s+(?:--platform=\S+\s+)?\S+@sha256:[0-9a-f]{64}\b", re.MULTILINE
)

# Directories deliberately left unwatched, each with the reason. An entry that stops
# being needed fails test_every_exemption_is_still_needed.
EXEMPT = {
    "tests/test_data/snapshot_fixture/repo": (
        "a fixture ASH scans in the snapshot tests; its bytes are part of the expected output"
    ),
}


def tracked_dockerfiles(root: Path = REPO_ROOT) -> dict[str, str]:
    listed = (
        subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"], check=True, capture_output=True
        )
        .stdout.decode("utf-8")
        .split("\0")
    )
    return {
        path: (root / path).read_text(encoding="utf-8", errors="replace")
        for path in listed
        if path and DOCKERFILE_NAME.match(Path(path).name) and (root / path).is_file()
    }


def pinned_directories(dockerfiles: dict[str, str]) -> set[str]:
    """Directories, relative and without slashes ("" for the root), of literal-pinned FROMs.

    A FROM that takes its image from an ARG is not counted: the digest then sits in an
    ARG default, which is a different thing for Dependabot to update. The root Dockerfile
    is that shape, and the root docker entry covers it.
    """
    found = set()
    for path, text in dockerfiles.items():
        if PINNED_FROM.search(text):
            parent = Path(path).parent.as_posix()
            found.add("" if parent == "." else parent)
    return found


def watched_directories(config: dict) -> set[str]:
    watched = set()
    for update in config.get("updates") or []:
        if update.get("package-ecosystem") != "docker":
            continue
        directories = update.get("directories") or [update.get("directory")]
        for directory in directories:
            if directory:
                watched.add(directory.strip("/"))
    return watched


def unwatched(dockerfiles: dict[str, str], config: dict) -> list[str]:
    return sorted(
        pinned_directories(dockerfiles) - watched_directories(config) - set(EXEMPT)
    )


@pytest.fixture(scope="module")
def config() -> dict:
    return yaml.safe_load(DEPENDABOT.read_text())


@pytest.fixture(scope="module")
def dockerfiles() -> dict[str, str]:
    return tracked_dockerfiles()


def test_the_census_found_pinned_dockerfiles(dockerfiles):
    # A census of nothing passes; the operator's two images must be in it.
    pinned = pinned_directories(dockerfiles)
    assert {
        "deploy/kubernetes-operator",
        "deploy/kubernetes-operator/tests/e2e",
    } <= pinned, pinned


def test_every_pinned_dockerfile_directory_is_watched(dockerfiles, config):
    missing = unwatched(dockerfiles, config)
    assert not missing, (
        f"Dockerfiles with a digest-pinned FROM in {missing}, which no docker entry in "
        f"{DEPENDABOT.relative_to(REPO_ROOT)} lists, so nothing will ever propose a new "
        f"digest. Add the directory to a docker entry, or to EXEMPT with the reason."
    )


def test_every_exemption_is_still_needed(dockerfiles, config):
    pinned = pinned_directories(dockerfiles)
    watched = watched_directories(config)
    stale = sorted(d for d in EXEMPT if d not in pinned or d in watched)
    assert not stale, f"EXEMPT entries that no longer apply: {stale}"


def test_every_watched_directory_exists(config):
    gone = sorted(
        d for d in watched_directories(config) if not (REPO_ROOT / d).is_dir()
    )
    assert not gone, f"docker entries for directories that do not exist: {gone}"


PLANTED = {"tools/new-image/Dockerfile": "FROM alpine:3@sha256:" + "a" * 64 + "\n"}


def test_a_planted_unwatched_dockerfile_is_reported(config):
    assert unwatched(PLANTED, config) == ["tools/new-image"]


def test_dropping_a_directory_from_its_entry_is_reported(dockerfiles, config):
    trimmed = yaml.safe_load(yaml.safe_dump(config))
    for update in trimmed["updates"]:
        if "/deploy/kubernetes-operator/tests/e2e" in (update.get("directories") or []):
            update["directories"].remove("/deploy/kubernetes-operator/tests/e2e")
    assert unwatched(dockerfiles, trimmed) == ["deploy/kubernetes-operator/tests/e2e"]


@pytest.mark.parametrize(
    "text",
    [
        "FROM python:3.12-slim\n",
        "ARG BASE=python@sha256:" + "b" * 64 + "\nFROM ${BASE}\n",
        "# FROM python@sha256:" + "c" * 64 + "\n",
    ],
)
def test_an_unpinned_from_is_not_counted(text):
    assert pinned_directories({"x/Dockerfile": text}) == set()


def test_a_multi_stage_and_platform_from_are_counted():
    text = (
        "FROM --platform=linux/amd64 python@sha256:"
        + "d" * 64
        + " AS build\nFROM build\n"
    )
    assert pinned_directories({"x/y/Dockerfile.ash": text}) == {"x/y"}
