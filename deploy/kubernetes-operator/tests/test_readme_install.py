"""The install commands in README.md, read the way kubectl would read them.

The README told adopters to run `kubectl apply -f generated/`. That directory also
holds config-schema-translation.json, the generator's report of what the CRD schema
could not express, which has no apiVersion or kind. kubectl decodes every .json,
.yaml and .yml file in a directory it is given, so the documented command failed
with "unable to decode ... Object 'Kind' is missing" on a file that was never meant
for a cluster. These tests expand each documented `kubectl apply -f` argument into
the files kubectl would read and require every one to be a Kubernetes object, and
require the commands to install every CRD the generator writes.
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path

import pytest
import yaml

from tests.test_least_privilege import KUBECTL_SUFFIXES, _flatten, _json_documents

OPERATOR_DIR = Path(__file__).resolve().parents[1]
README = OPERATOR_DIR / "README.md"
GENERATED_DIR = OPERATOR_DIR / "generated"

FENCE = re.compile(r"^```[^\n]*\n(.*?)^```", re.MULTILINE | re.DOTALL)


def documented_apply_targets(readme: str) -> list[str]:
    # Every -f/--filename argument of every `kubectl apply` line in a fenced block.
    targets = []
    for block in FENCE.findall(readme):
        for line in block.splitlines():
            # Only these lines are split: other lines in the README's blocks are not
            # shell and need not tokenize.
            if not line.lstrip().startswith("kubectl apply"):
                continue
            words = shlex.split(line, comments=True)
            for index, word in enumerate(words):
                if word in ("-f", "--filename"):
                    targets.append(words[index + 1])
                elif word.startswith(("-f=", "--filename=")):
                    targets.append(word.split("=", 1)[1])
    return targets


def files_kubectl_reads(target: str, base: Path = OPERATOR_DIR) -> list[Path]:
    # A directory is read one level deep, every file with a manifest suffix. A glob
    # is expanded by the shell before kubectl sees it.
    path = base / target
    if path.is_dir():
        return sorted(p for p in path.iterdir() if p.is_file() and p.suffix in KUBECTL_SUFFIXES)
    matches = sorted(base.glob(target))
    assert matches, f"`kubectl apply -f {target}` names nothing that exists"
    return matches


def objects_in(path: Path) -> list:
    text = path.read_text()
    raw = _json_documents(text) if path.suffix == ".json" else list(yaml.safe_load_all(text))
    return [obj for doc in raw if doc for obj in _flatten(doc, path)]


@pytest.fixture(scope="module")
def applied_files() -> list[Path]:
    targets = documented_apply_targets(README.read_text())
    assert targets, "README.md documents no `kubectl apply -f` command, so this checks nothing"
    return [path for target in targets for path in files_kubectl_reads(target)]


def test_every_file_the_install_commands_apply_is_a_kubernetes_object(applied_files):
    not_objects = [
        f"{path.relative_to(OPERATOR_DIR)}: {sorted(obj) if isinstance(obj, dict) else obj!r}"
        for path in applied_files
        for obj in objects_in(path)
        if not (isinstance(obj, dict) and obj.get("apiVersion") and obj.get("kind"))
    ]
    assert not not_objects, f"kubectl would fail to decode: {not_objects}"


def test_the_install_commands_apply_every_generated_crd(applied_files):
    crds = set(GENERATED_DIR.glob("crd-*.yaml"))
    assert crds, "generated/ holds no CRD, so this checks nothing"
    assert crds <= set(applied_files), (
        f"README.md does not install {sorted(p.name for p in crds - set(applied_files))}"
    )


def test_the_check_refuses_a_directory_holding_a_non_object(tmp_path):
    # The control: the README's old `kubectl apply -f generated/`, against a copy of
    # generated/ as the generator leaves it, is refused.
    (tmp_path / "generated").mkdir()
    for path in GENERATED_DIR.iterdir():
        (tmp_path / "generated" / path.name).write_bytes(path.read_bytes())
    (target,) = documented_apply_targets("```\nkubectl apply -f generated/  # the CRDs\n```\n")
    files = files_kubectl_reads(target, base=tmp_path)
    assert tmp_path / "generated" / "config-schema-translation.json" in files
    assert not all(obj.get("kind") for path in files for obj in objects_in(path))
