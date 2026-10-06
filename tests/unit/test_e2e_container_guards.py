# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The checks the container e2e channel relies on, run without docker.

scripts/e2e/container.sh needs docker and a long image build, so it only runs in CI.
The two judgments it makes that are not assert_outcome's are tested here instead:
.github/scripts/assert-no-image-publish.py (nothing CI runs may push an image) and
scripts/e2e/image_provenance.py (an image carries a given tree's code). Each is shown
rejecting what it exists to reject, and the publish census is run on this tree.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None, path
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


publish = _load(
    REPO_ROOT / ".github" / "scripts" / "assert-no-image-publish.py",
    "ash_assert_no_image_publish",
)
provenance = _load(
    REPO_ROOT / "scripts" / "e2e" / "image_provenance.py", "ash_e2e_image_provenance"
)


def test_publish_guard_self_test_passes(capsys):
    assert publish.self_test() == 0
    assert "SELF-TEST PASS" in capsys.readouterr().out


def test_publish_guard_passes_on_this_tree(capsys):
    files = publish.tracked_files(REPO_ROOT)
    assert publish.check(REPO_ROOT, files, publish.EXEMPT) == 0, capsys.readouterr().out


def test_publish_guard_reads_the_container_channel():
    files = publish.tracked_files(REPO_ROOT)
    for required in publish.REQUIRED:
        assert required in files


@pytest.mark.parametrize(
    "line",
    [
        "        run: docker push ghcr.io/example/ash:latest",
        "          push: true",
        "      - uses: docker/login-action@0123456789abcdef0123456789abcdef01234567 # v3",
        "  sudo nerdctl push example/ash",
        "  docker buildx build -t example/ash --push .",
        '"$OCI" push "$TAG_FRESH"',
        "$OCI image push example/ash",
        '"${RUNNER}" login ghcr.io',
        "  --push \\",
        "docker manifest push ghcr.io/example/ash",
        "docker buildx imagetools create -t ghcr.io/example/ash:1 example/ash:1",
    ],
)
def test_publish_guard_fails_a_planted_push(tmp_path, capsys, line):
    rel = "scripts/e2e/planted.sh"
    (tmp_path / "scripts" / "e2e").mkdir(parents=True)
    (tmp_path / rel).write_text(f"{line}\n", encoding="utf-8")
    assert publish.check(tmp_path, [rel], {}) == 1
    assert "planted.sh:1" in capsys.readouterr().out


def test_publish_guard_ignores_comments(tmp_path):
    rel = "scripts/e2e/commented.sh"
    (tmp_path / "scripts" / "e2e").mkdir(parents=True)
    (tmp_path / rel).write_text("# never docker push this image\n", encoding="utf-8")
    hits, stale, read = publish.scan(tmp_path, [rel], {})
    assert (hits, stale, read) == ([], [], 1)


def test_publish_guard_fails_a_stale_exemption(tmp_path, capsys):
    rel = "scripts/e2e/clean.sh"
    (tmp_path / "scripts" / "e2e").mkdir(parents=True)
    (tmp_path / rel).write_text("docker build .\n", encoding="utf-8")
    exempt = {(rel, "push: true"): "matches nothing"}
    assert publish.check(tmp_path, [rel], exempt) == 1
    assert "exemption matches no line" in capsys.readouterr().out


def test_publish_guard_excludes_deploy_but_covers_ci_roots():
    assert publish.in_scope(".github/workflows/ash-e2e.yml")
    assert publish.in_scope("scripts/e2e/container.sh")
    assert publish.in_scope("packaging/deb/verify-in-container.sh")
    assert not publish.in_scope("deploy/cdk/lib/ash-image-build.ts")
    assert not publish.in_scope(".github/scripts/assert-no-image-publish.py")


def test_provenance_self_test_passes(capsys):
    assert provenance.self_test() == 0
    assert "SELF-TEST PASS" in capsys.readouterr().out


def test_provenance_compare_accepts_this_tree_and_rejects_a_change(tmp_path):
    package = REPO_ROOT / "automated_security_helper"
    installed = provenance.manifest(package)
    assert installed, "the package has no *.py files"
    good = tmp_path / "good.json"
    good.write_text(json.dumps(installed), encoding="utf-8")
    assert (
        provenance.main(["compare", "--source", str(package), "--installed", str(good)])
        == 0
    )

    changed = dict(installed)
    first = min(changed)
    changed[first] = "0" * 64
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(changed), encoding="utf-8")
    assert (
        provenance.main(["compare", "--source", str(package), "--installed", str(bad)])
        == 1
    )


def test_provenance_manifest_by_package_matches_by_directory(capsys):
    assert provenance.main(["manifest", "--package", "automated_security_helper"]) == 0
    by_package = json.loads(capsys.readouterr().out)
    import automated_security_helper

    by_dir = provenance.manifest(Path(automated_security_helper.__file__).parent)
    assert by_package == by_dir


def test_provenance_manifest_refuses_both_or_neither():
    assert provenance.main(["manifest"]) == 3
    assert provenance.main(["manifest", ".", "--package", "json"]) == 3
