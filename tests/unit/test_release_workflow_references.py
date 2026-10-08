# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every output, input and secret the release workflows reference is one that exists.

WHY THIS EXISTS

ash-release-assets.yml once exported `${{ steps.upload.outputs.artifact }}`.
actions/upload-artifact declares artifact-id, artifact-url and artifact-digest, and
no `artifact`, so the expression was the empty string. ash-tag-on-merge.yml handed
that to download-artifact as `name:`, and download-artifact with no name downloads
every artifact of the run, each into its own subdirectory. The release could never
publish. actionlint passed (it does not know the outputs of a SHA-pinned action),
and so did every structural test, because each one checked a step's shape rather
than whether the name it read was ever written.

WHAT IT CHECKS, in .github/workflows/ash-{release-assets,tag-on-merge,package,
native-packages}.yml, the release and the workflows it calls:

* `steps.<id>.outputs.<name>`: the step exists in the job, and declares <name>. For
  an action, the pinned commit's action.yml declares it; for a `run:` step, the
  script writes `<name>=` or `<name><<` and mentions GITHUB_OUTPUT.
* `needs.<job>.outputs.<name>`: <job> is in `needs:` and declares <name>, in its
  `outputs:` or, for a reusable-workflow job, in the callee's workflow_call outputs.
* `jobs.<job>.outputs.<name>` in a workflow_call output: the job declares it.
* `inputs.<name>`: the workflow declares it under workflow_call or workflow_dispatch.
* every `with:` key of an action step is an input the pinned action.yml declares,
  and every `with:`/`secrets:` key of a reusable-workflow call is one the callee
  declares.

Action interfaces come from tests/unit/fixtures/pinned_action_interfaces.json, a
snapshot of each pinned commit's action.yml, so the test needs no network. Every pin
the release workflows use must be in it, so bumping a pin fails here until the
snapshot is refreshed for the new commit:

    python tests/unit/test_release_workflow_references.py --refresh

which fetches action.yml at each pinned SHA from raw.githubusercontent.com.

WHAT IT DOES NOT CHECK

Expressions outside `${{ }}` and `if:` (a shell comment naming an output is not a
reference), matrix values, and outputs of local composite actions (the release
workflows use none). A pass means every name read is a name declared, not that the
value is what the reader wants.
"""

from __future__ import annotations

import copy
import json
import re
import sys
import urllib.request
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
SNAPSHOT = (
    Path(__file__).resolve().parent / "fixtures" / "pinned_action_interfaces.json"
)

# The release, and the workflows it calls.
RELEASE_WORKFLOWS: Tuple[str, ...] = (
    "ash-tag-on-merge.yml",
    "ash-release-assets.yml",
    "ash-package.yml",
    "ash-native-packages.yml",
)

_EXPR = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)
_NAME = r"[A-Za-z_][A-Za-z0-9_-]*"
_STEP_OUT = re.compile(rf"\bsteps\.({_NAME})\.outputs\.({_NAME})")
_NEEDS_OUT = re.compile(rf"\bneeds\.({_NAME})\.outputs\.({_NAME})")
_JOBS_OUT = re.compile(rf"\bjobs\.({_NAME})\.outputs\.({_NAME})")
_INPUT = re.compile(rf"(?<![\w.-])inputs\.({_NAME})")
_WRITTEN = re.compile(rf"""(?:echo|printf)\s+(?:-[a-z]+\s+)*['"]?({_NAME})(?:=|<<)""")

Interfaces = Dict[str, Dict[str, List[str]]]


def load_workflow(path: Path) -> dict:
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    # PyYAML reads the bare `on:` key as the boolean True.
    if True in doc:
        doc["on"] = doc.pop(True)
    return doc


def load_release_workflows() -> Dict[str, dict]:
    return {name: load_workflow(WORKFLOWS / name) for name in RELEASE_WORKFLOWS}


def load_interfaces() -> Interfaces:
    return json.loads(SNAPSHOT.read_text(encoding="utf-8"))["actions"]


def _strings(node: object) -> Iterator[str]:
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for value in node.values():
            yield from _strings(value)
    elif isinstance(node, list):
        for value in node:
            yield from _strings(value)


def _expressions(node: object) -> Iterator[str]:
    """Every `${{ }}` body under NODE, plus every `if:` value, which is one bare."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "if" and isinstance(value, str):
                yield value
            else:
                yield from _expressions(value)
    elif isinstance(node, list):
        for value in node:
            yield from _expressions(value)
    elif isinstance(node, str):
        yield from (m.group(1) for m in _EXPR.finditer(node))


def _remote(uses: str) -> bool:
    return "@" in uses and not uses.startswith(("./", "docker://"))


def _local_workflow(uses: str) -> Optional[str]:
    if uses.startswith("./.github/workflows/"):
        return uses[len("./.github/workflows/") :]
    return None


def _call(doc: dict) -> dict:
    on = doc.get("on") or {}
    return (on.get("workflow_call") or {}) if isinstance(on, dict) else {}


def _declared_inputs(doc: dict) -> set:
    on = doc.get("on") or {}
    names: set = set()
    if isinstance(on, dict):
        for trigger in ("workflow_call", "workflow_dispatch"):
            names |= set(((on.get(trigger) or {}).get("inputs") or {}).keys())
    return names


def _job_outputs(job: dict, docs: Dict[str, dict]) -> Optional[set]:
    """The output names a job declares, or None when the callee is not loaded."""
    callee = _local_workflow(str(job.get("uses", "")))
    if callee is not None:
        if callee not in docs:
            return None
        return set((_call(docs[callee]).get("outputs") or {}).keys())
    return set((job.get("outputs") or {}).keys())


def _step_outputs(step: dict, interfaces: Interfaces) -> Tuple[Optional[set], str]:
    uses = str(step.get("uses", ""))
    if uses:
        if uses not in interfaces:
            return None, f"{uses} is not in {SNAPSHOT.name}"
        return set(interfaces[uses]["outputs"]), uses
    run = str(step.get("run", ""))
    if "GITHUB_OUTPUT" not in run:
        return set(), "a run step that never writes GITHUB_OUTPUT"
    return set(_WRITTEN.findall(run)), "its run script"


def check(docs: Dict[str, dict], interfaces: Interfaces) -> List[str]:
    findings: List[str] = []
    for wf_name, doc in docs.items():
        jobs = doc.get("jobs") or {}
        inputs = _declared_inputs(doc)

        for expr in _expressions(doc):
            for name in _INPUT.findall(expr):
                if name not in inputs:
                    findings.append(f"{wf_name}: inputs.{name} is not a declared input")

        for out_name, out in (_call(doc).get("outputs") or {}).items():
            for job_id, name in _JOBS_OUT.findall(str(out.get("value", ""))):
                if job_id not in jobs:
                    findings.append(
                        f"{wf_name}: output {out_name} reads jobs.{job_id}, "
                        "which is not a job"
                    )
                    continue
                declared = _job_outputs(jobs[job_id], docs)
                if declared is not None and name not in declared:
                    findings.append(
                        f"{wf_name}: output {out_name} reads jobs.{job_id}.outputs.{name}, "
                        f"which {job_id} does not declare ({sorted(declared)})"
                    )

        for job_id, job in jobs.items():
            needs = job.get("needs") or []
            needs = [needs] if isinstance(needs, str) else list(needs)
            steps = job.get("steps") or []
            by_id = {s["id"]: s for s in steps if isinstance(s, dict) and "id" in s}
            where = f"{wf_name}: job {job_id}"

            for expr in _expressions(job):
                for step_id, name in _STEP_OUT.findall(expr):
                    step = by_id.get(step_id)
                    if step is None:
                        findings.append(
                            f"{where} reads steps.{step_id}.outputs.{name}, "
                            f"and no step has id {step_id}"
                        )
                        continue
                    declared, source = _step_outputs(step, interfaces)
                    if declared is None:
                        findings.append(f"{where}: step {step_id}: {source}")
                    elif name not in declared:
                        findings.append(
                            f"{where} reads steps.{step_id}.outputs.{name}, which "
                            f"{source} does not declare ({sorted(declared)})"
                        )
                for need, name in _NEEDS_OUT.findall(expr):
                    if need not in needs:
                        findings.append(
                            f"{where} reads needs.{need}.outputs.{name}, "
                            f"and {need} is not in its needs ({needs})"
                        )
                        continue
                    if need not in jobs:
                        findings.append(f"{where} needs {need}, which is not a job")
                        continue
                    declared = _job_outputs(jobs[need], docs)
                    if declared is not None and name not in declared:
                        findings.append(
                            f"{where} reads needs.{need}.outputs.{name}, which "
                            f"{need} does not declare ({sorted(declared)})"
                        )

            callee = _local_workflow(str(job.get("uses", "")))
            if callee is not None and callee in docs:
                call = _call(docs[callee])
                for key in (job.get("with") or {}).keys():
                    if key not in (call.get("inputs") or {}):
                        findings.append(
                            f"{where} passes input {key}, which {callee} does not declare"
                        )
                secrets = job.get("secrets") or {}
                if isinstance(secrets, dict):
                    for key in secrets.keys():
                        if key not in (call.get("secrets") or {}):
                            findings.append(
                                f"{where} passes secret {key}, which {callee} does not declare"
                            )

            for index, step in enumerate(steps):
                uses = str(step.get("uses", "")) if isinstance(step, dict) else ""
                if not _remote(uses):
                    continue
                label = step.get("id") or step.get("name") or f"#{index}"
                if uses not in interfaces:
                    findings.append(
                        f"{where}: step {label} uses {uses}, which is not in "
                        f"{SNAPSHOT.name}; refresh the snapshot for this pin"
                    )
                    continue
                accepted = set(interfaces[uses]["inputs"])
                for key in (step.get("with") or {}).keys():
                    if key not in accepted:
                        findings.append(
                            f"{where}: step {label} passes {key} to {uses}, which "
                            f"declares no such input ({sorted(accepted)})"
                        )
    return findings


def remote_pins(docs: Dict[str, dict]) -> set:
    pins = set()
    for doc in docs.values():
        for job in (doc.get("jobs") or {}).values():
            for step in job.get("steps") or []:
                uses = str(step.get("uses", "")) if isinstance(step, dict) else ""
                if _remote(uses):
                    pins.add(uses)
    return pins


# -- tests -------------------------------------------------------------------


def test_every_reference_in_the_release_workflows_names_something_declared():
    assert check(load_release_workflows(), load_interfaces()) == []


def test_the_check_sees_the_references_the_release_depends_on():
    # Not vacuous: the pass above covers the chain the original defect broke, from
    # the upload step to the download in the release job.
    docs = load_release_workflows()
    seen = set()
    for doc in docs.values():
        for expr in _expressions(doc):
            seen |= {("steps",) + m for m in _STEP_OUT.findall(expr)}
            seen |= {("needs",) + m for m in _NEEDS_OUT.findall(expr)}
            seen |= {("jobs",) + m for m in _JOBS_OUT.findall(expr)}
    for ref in (
        ("steps", "upload", "artifact-id"),
        ("jobs", "assemble", "artifact-id"),
        ("needs", "assets", "artifact-id"),
        ("needs", "assets", "sums"),
        ("steps", "gate", "sums"),
        ("needs", "resolve", "sha"),
    ):
        assert ref in seen, ref
    assert len(seen) >= 16, sorted(seen)


def test_the_snapshot_holds_exactly_the_pins_the_release_workflows_use():
    assert sorted(load_interfaces()) == sorted(remote_pins(load_release_workflows()))


def test_the_snapshot_declares_upload_artifacts_real_outputs():
    # The fact the original defect turned on, pinned so a hand-edited snapshot
    # cannot quietly add an `artifact` output.
    uploads = [k for k in load_interfaces() if k.startswith("actions/upload-artifact@")]
    assert uploads
    for key in uploads:
        assert sorted(load_interfaces()[key]["outputs"]) == [
            "artifact-digest",
            "artifact-id",
            "artifact-url",
        ]


def _planted(mutate) -> List[str]:
    docs = copy.deepcopy(load_release_workflows())
    interfaces = copy.deepcopy(load_interfaces())
    mutate(docs, interfaces)
    return check(docs, interfaces)


def test_plant_the_original_defect_an_undeclared_upload_output():
    def mutate(docs, _):
        docs["ash-release-assets.yml"]["jobs"]["assemble"]["outputs"]["artifact-id"] = (
            "${{ steps.upload.outputs.artifact }}"
        )

    findings = _planted(mutate)
    assert any(
        "steps.upload.outputs.artifact," in f and "upload-artifact@" in f
        for f in findings
    ), findings


def test_plant_a_caller_reading_an_output_the_called_workflow_does_not_export():
    def mutate(docs, _):
        for step in docs["ash-tag-on-merge.yml"]["jobs"]["tag-and-release"]["steps"]:
            if str(step.get("uses", "")).startswith("actions/download-artifact@"):
                step["with"]["artifact-ids"] = "${{ needs.assets.outputs.artifact }}"

    findings = _planted(mutate)
    assert any("needs.assets.outputs.artifact," in f for f in findings), findings


def test_plant_a_workflow_call_output_reading_an_undeclared_job_output():
    def mutate(docs, _):
        outputs = _call(docs["ash-release-assets.yml"])["outputs"]
        outputs["artifact-id"]["value"] = "${{ jobs.assemble.outputs.artifact }}"

    findings = _planted(mutate)
    assert any("jobs.assemble.outputs.artifact," in f for f in findings), findings


def test_plant_an_input_the_pinned_action_does_not_declare():
    def mutate(docs, _):
        for step in docs["ash-tag-on-merge.yml"]["jobs"]["tag-and-release"]["steps"]:
            if str(step.get("uses", "")).startswith("actions/download-artifact@"):
                step["with"]["artifact-id"] = step["with"].pop("artifact-ids")

    findings = _planted(mutate)
    assert any(
        "passes artifact-id to actions/download-artifact@" in f for f in findings
    ), findings


def test_plant_a_run_step_output_its_script_never_writes():
    def mutate(docs, _):
        job = docs["ash-release-assets.yml"]["jobs"]["assemble"]
        job["outputs"]["version"] = "${{ steps.version.outputs.ver }}"

    findings = _planted(mutate)
    assert any(
        "steps.version.outputs.ver," in f and "run script" in f for f in findings
    ), findings


def test_plant_a_step_id_that_does_not_exist():
    def mutate(docs, _):
        docs["ash-release-assets.yml"]["jobs"]["assemble"]["outputs"]["sums"] = (
            "${{ steps.gates.outputs.sums }}"
        )

    findings = _planted(mutate)
    assert any("no step has id gates" in f for f in findings), findings


def test_plant_a_needs_output_from_a_job_not_in_needs():
    def mutate(docs, _):
        job = docs["ash-tag-on-merge.yml"]["jobs"]["tag-and-release"]
        job["needs"] = ["resolve"]

    findings = _planted(mutate)
    assert any("assets is not in its needs" in f for f in findings), findings


def test_plant_an_undeclared_workflow_input_and_call_argument():
    def mutate(docs, _):
        jobs = docs["ash-release-assets.yml"]["jobs"]
        jobs["package"]["with"]["refs"] = "${{ inputs.refs }}"

    findings = _planted(mutate)
    assert any("inputs.refs is not a declared input" in f for f in findings), findings
    assert any("passes input refs, which ash-package.yml" in f for f in findings), (
        findings
    )


def test_plant_a_pin_the_snapshot_does_not_hold():
    def mutate(_, interfaces):
        for key in [
            k for k in interfaces if k.startswith("actions/download-artifact@")
        ]:
            del interfaces[key]

    findings = _planted(mutate)
    assert any("refresh the snapshot" in f for f in findings), findings


# -- refreshing the snapshot -------------------------------------------------


def _fetch_interface(pin: str) -> Dict[str, List[str]]:
    repo, sha = pin.split("@", 1)
    owner_repo = "/".join(repo.split("/")[:2])
    subpath = "/".join(repo.split("/")[2:])
    for filename in ("action.yml", "action.yaml"):
        path = f"{subpath}/{filename}" if subpath else filename
        url = f"https://raw.githubusercontent.com/{owner_repo}/{sha}/{path}"
        try:
            with urllib.request.urlopen(url, timeout=30) as response:  # nosec B310 - fixed https host
                meta = yaml.safe_load(response.read().decode("utf-8"))
        except OSError:
            continue
        return {
            "source": url,
            "inputs": sorted((meta.get("inputs") or {}).keys()),
            "outputs": sorted((meta.get("outputs") or {}).keys()),
        }
    raise SystemExit(f"no action.yml or action.yaml for {pin}")


def refresh() -> int:
    pins = sorted(remote_pins(load_release_workflows()))
    actions = {pin: _fetch_interface(pin) for pin in pins}
    SNAPSHOT.parent.mkdir(parents=True, exist_ok=True)
    SNAPSHOT.write_text(
        json.dumps(
            {
                "about": (
                    "Inputs and outputs of each action the release workflows pin, read "
                    "from action.yml at the pinned commit. Regenerate with "
                    "`python tests/unit/test_release_workflow_references.py --refresh`."
                ),
                "actions": actions,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"wrote {len(actions)} action interface(s) to {SNAPSHOT}")
    return 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--refresh"]:
        sys.exit(refresh())
    sys.exit("usage: test_release_workflow_references.py --refresh")
