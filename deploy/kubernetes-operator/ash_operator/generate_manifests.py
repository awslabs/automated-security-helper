"""Generate the committed CRDs, and check them for drift.

Same pattern the repository already uses for its CDK templates and buildspecs, and
for the same reason: the generated files are the deliverable. An adopter runs
``kubectl apply -f deploy/kubernetes-operator/generated/`` against a file in the
repository; they do not run this generator. That only works if what is committed is
exactly what this module emits, which is what ``--check`` is for.

**``--check`` compares content in memory and asks git nothing.** That is a
correction, and the reason is worth keeping because the original design looked
careful and was wrong twice over.

It used to run ``git status --porcelain --untracked-files=all -- <dir>`` and treat
empty output as agreement. Git answers about *tracking state*, not content, and those
are different questions:

* ``--untracked-files=all`` does not list **ignored** paths; that needs ``--ignored``.
  Measured in a scratch repo with ``generated/`` ignored and the file's content
  replaced wholesale: the query returns nothing, so the gate printed "N generated
  file(s) match the committed copies byte for byte" and exited 0 **having compared
  nothing**. This repository's ``.gitignore`` is 300-plus lines of concatenated
  templates, so one rule touching ``generated/`` was all it would have taken.
* The inverse also fired. An untracked but byte-identical file reports ``??``, so the
  gate failed for files that matched exactly what the generator emits, and no amount
  of regenerating could clear it -- only ``git add`` could.

And the check made itself circular: it called ``write_all()`` first, overwriting the
committed files, and only then asked git. In the ignored case there was nothing left
to compare even in principle.

So the oracle is now the bytes. ``render_all()`` produces ``filename -> content``
without touching the disk, ``check()`` reads what is there and diffs it in memory, and
``--check`` **writes nothing at all** -- a check that modifies the tree it is checking
cannot be trusted and is hostile in CI.

What the git-based version was reaching for still holds, by a better route. A CRD
generated but never committed is absent from a clean CI checkout, so the in-memory
comparison reports it missing -- which is the same verdict without depending on the
local worktree's git state. An orphan whose kind was removed is on disk and not in
``render_all()``, so it is reported as an orphan rather than inferred from a deletion
git noticed. Every generated file is compared, not just the largest, so drift confined
to a sibling is caught. And the zero-artifacts guard stays: a gate that compared
nothing must not report success.

Tracking state is deliberately not consulted. Whether a file is committed is a
question for review, not for a content gate, and conflating them is what produced both
failure modes above.

Reproducibility: the output depends only on this module, ``ash_operator.crd_schema``
and ASH's ``AshConfig`` JSON Schema. It is reproducible *for a fixed schema* --
upgrading ASH legitimately changes ``spec.config``, and that is a real diff to review
rather than drift to suppress. A digest of that input schema is annotated on each CRD
so the diff says which upgrade caused it, and it is a digest rather than a version
number for the reason given in :func:`_annotations`.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml

from ash_operator.constants import (
    GROUP,
    MAX_SHARD_COUNT,
    MCP_KIND,
    MCP_PLURAL,
    MCP_SINGULAR,
    NON_TERMINAL_PHASES,
    SCAN_KIND,
    SCAN_PLURAL,
    SCAN_SINGULAR,
    SEVERITY_LEVELS,
    TERMINAL_PHASES,
    VERSION,
)
from ash_operator.crd_schema import build_config_schema

GENERATED_DIR = Path(__file__).resolve().parent.parent / "generated"
GENERATED_GLOB = "crd-*.yaml"
TRANSLATION_REPORT = "config-schema-translation.json"


def _annotations(config_schema_digest: str) -> dict[str, str]:
    """Annotations every generated CRD carries.

    The digest is of the AshConfig JSON Schema the CRD was generated from, not the
    installed ASH version. A version annotation would differ between a CRD generated
    with ASH importable and one generated from the committed schema, so the drift
    gate would fail for two people who produced byte-identical output. The digest is
    the same either way, and it answers the question the annotation is for: which ASH
    config surface does this CRD express.
    """
    return {
        f"{GROUP}/generated-by": "python -m ash_operator.generate_manifests",
        f"{GROUP}/ash-config-schema-sha256": config_schema_digest,
    }


def _source_volume_schema() -> dict[str, Any]:
    """The subset of ``VolumeSource`` an adopter may use for the scanned tree.

    Narrowed on purpose rather than mirroring the full Kubernetes union. Two of the
    omitted members would be a security regression in a tool whose whole job is to
    scan untrusted code: ``hostPath`` mounts the node's filesystem into a pod that
    is about to run third-party scanners over foreign input, and ``emptyDir``
    describes a tree that nothing ever populated, which scans clean and looks
    successful. The rest are omitted because ``x-kubernetes-preserve-unknown-fields``
    would accept them anyway and this list is what the operator has actually been
    exercised with.
    """
    return {
        "type": "object",
        "description": (
            "Volume carrying the source tree to scan, mounted read-only at "
            "/workspace/src. hostPath and emptyDir are deliberately not offered: the "
            "first hands a node's filesystem to a pod running third-party scanners "
            "over foreign code, and the second describes an empty tree, which scans "
            "clean and reads as success."
        ),
        "properties": {
            "persistentVolumeClaim": {
                "type": "object",
                "properties": {
                    "claimName": {"type": "string"},
                    "readOnly": {"type": "boolean"},
                },
                "required": ["claimName"],
            },
            "configMap": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "defaultMode": {"type": "integer"},
                    "optional": {"type": "boolean"},
                },
                "required": ["name"],
            },
            "secret": {
                "type": "object",
                "properties": {
                    "secretName": {"type": "string"},
                    "defaultMode": {"type": "integer"},
                    "optional": {"type": "boolean"},
                },
                "required": ["secretName"],
            },
            "csi": {
                "type": "object",
                "properties": {
                    "driver": {"type": "string"},
                    "readOnly": {"type": "boolean"},
                    "fsType": {"type": "string"},
                    "volumeAttributes": {
                        "type": "object",
                        "additionalProperties": {"type": "string"},
                    },
                },
                "required": ["driver"],
            },
        },
    }


def _resources_schema(description: str) -> dict[str, Any]:
    quantity = {"type": "string", "x-kubernetes-int-or-string": True}
    return {
        "type": "object",
        "description": description,
        "properties": {
            "limits": {"type": "object", "additionalProperties": quantity},
            "requests": {"type": "object", "additionalProperties": quantity},
        },
    }


def build_scan_crd() -> tuple[dict[str, Any], dict[str, Any]]:
    config_schema, translation = build_config_schema()
    spec: dict[str, Any] = {
        "type": "object",
        "required": ["image", "shardCount", "source"],
        "properties": {
            "image": {
                "type": "string",
                "minLength": 1,
                "description": (
                    "ASH container image. Required with no default: ASH publishes no "
                    "image to any public registry and will not, so every deployment "
                    "builds its own. Installing ASH by distribution name is also "
                    "wrong -- the name automated-security-helper on PyPI is an "
                    "unrelated placeholder, so a name-based install succeeds, leaves "
                    "no ash on PATH, and puts a third party's code in the scan "
                    "container."
                ),
            },
            "imagePullPolicy": {
                "type": "string",
                "enum": ["Always", "IfNotPresent", "Never"],
            },
            "shardCount": {
                "type": "integer",
                "minimum": 1,
                "maximum": MAX_SHARD_COUNT,
                "description": (
                    "How many shards to split the scanner list across. The partition "
                    "is round-robin over the sorted, deduplicated, lower-cased "
                    "scanner names, so a count above the scanner count gives the "
                    "surplus shards an empty assignment -- wasteful, not wrong. The "
                    f"ceiling of {MAX_SHARD_COUNT} exists so a typo is rejected "
                    "rather than scheduling hundreds of empty pods."
                ),
            },
            "parallelism": {
                "type": "integer",
                "minimum": 1,
                "description": (
                    "Job parallelism. Defaults to shardCount. Lower it to run shards "
                    "in waves on a small cluster, or to make a ReadWriteOnce results "
                    "volume workable."
                ),
            },
            "source": _source_volume_schema(),
            "results": {
                "type": "object",
                "description": (
                    "Where shard results are published and the merge reads them. "
                    "Defaults to a PVC the operator creates and owns. Supply "
                    "claimName to reuse your own."
                ),
                "properties": {
                    "claimName": {"type": "string"},
                    "size": {"type": "string"},
                    "storageClassName": {"type": "string"},
                    "accessModes": {"type": "array", "items": {"type": "string"}},
                },
            },
            "scanners": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Passed to every shard as --scanners. Setting it pins the roster "
                    "identically on every pod, which is a second guard against the "
                    "split-brain case where two pods partition different scanner "
                    "sets; the run's immutable, content-addressed ConfigMap is the "
                    "first."
                ),
            },
            "excludeScanners": {"type": "array", "items": {"type": "string"}},
            "extraScanArguments": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Extra `ash scan` flags. --shard-index, --shard-count, "
                    "--source-dir, --output-dir, --min-severity, --fail-on-findings "
                    "and --fail-on-incomplete-scanners are refused here: the first "
                    "four are computed by the operator, and the last three decide "
                    "the run's verdict, which belongs to the merge. A shard runs "
                    "only its slice, so a shard that finds nothing exits 0 no matter "
                    "what the others found."
                ),
            },
            "minSeverity": {
                "type": "string",
                "enum": list(SEVERITY_LEVELS),
                "description": (
                    "Severity floor for the merged verdict, passed to `ash merge` "
                    "only. On `ash scan` it changes just that scan's exit code, and a "
                    "shard's exit code is discarded, so setting it per shard would "
                    "read as a gate that never fires."
                ),
            },
            "failOnFindings": {"type": "boolean"},
            "failOnIncompleteScanners": {
                "type": "boolean",
                "description": (
                    "Passed to `ash merge`. ASH's own default is true, so leaving "
                    "this unset ends a scan whose scanners did not all run in phase "
                    "Incomplete (merge exit 1) with its partial results in .status. "
                    "Setting it false accepts the gap: the phase then follows the "
                    "findings alone, and .status.coverageComplete and "
                    ".status.incompleteScanners still name what did not run."
                ),
            },
            "outputFormats": {"type": "array", "items": {"type": "string"}},
            "backoffLimit": {
                "type": "integer",
                "minimum": 0,
                "description": (
                    "Shard Job backoffLimit, default 0. Retries are safe here: each "
                    "attempt publishes to an attempt-qualified, immutable directory, "
                    "so a retry cannot overwrite a completed shard and the collector "
                    "picks one deterministically. 0 is still the default because it "
                    "is the option that needs no reasoning about."
                ),
            },
            "collectBackoffLimit": {"type": "integer", "minimum": 0},
            "ttlSecondsAfterFinished": {"type": "integer", "minimum": 0},
            "runAsUser": {"type": "integer", "minimum": 1},
            "fsGroup": {"type": "integer", "minimum": 1},
            "scanServiceAccountName": {
                "type": "string",
                "description": (
                    "ServiceAccount for the shard and collector pods. Defaults to "
                    "ash-scan, which manifests/rbac.yaml creates with no rules. Its "
                    "token is never mounted (automountServiceAccountToken: false) -- a "
                    "pod running scanners over foreign source has no business holding "
                    "an API credential, and nothing in the scan path calls the API."
                ),
            },
            "resources": _resources_schema("Resources for each shard pod."),
            "collectResources": _resources_schema(
                "Resources for the collector pod. Defaults to spec.resources."
            ),
            "config": config_schema,
        },
    }

    status = {
        "type": "object",
        "x-kubernetes-preserve-unknown-fields": True,
        "properties": {
            "phase": {
                "type": "string",
                "enum": [*NON_TERMINAL_PHASES, *TERMINAL_PHASES],
                "description": (
                    "The terminal phases are ash merge's three answers and one "
                    "refusal. Clean is exit 0. Findings is exit 2. Incomplete is exit "
                    "1 over a merged report that names a coverage gap: partial "
                    "results, real findings from a set known to be short. Refused "
                    "means the operator does not have an answer and is declining to "
                    "synthesise one -- a missing shard, a merge that wrote no report, "
                    "exit 1 with no coverage gap, or a collector summary it could "
                    "not read."
                ),
            },
            "exitCode": {
                "type": "integer",
                "nullable": True,
                "description": "ash merge's exit code: 0 clean, 2 findings, 1 incomplete.",
            },
            "coverageComplete": {
                "type": "boolean",
                "nullable": True,
                "description": (
                    "Whether the merged report covered everything, assessed the way "
                    "ASH answers coverage_complete for an MCP scan. Reported whatever "
                    "failOnIncompleteScanners says; null when it could not be assessed."
                ),
            },
            "coverageSource": {"type": "string", "nullable": True},
            "coverageGaps": {"type": "array", "items": {"type": "string"}},
            "shardCount": {"type": "integer"},
            "resultsPrefix": {"type": "string"},
            "resultsClaimName": {"type": "string"},
            "configMapName": {"type": "string"},
            "shardJobName": {"type": "string"},
            "collectJobName": {"type": "string"},
            "incompleteScanners": {"type": "array", "items": {"type": "string"}},
            "scannerCompleteness": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "status": {"type": "string"},
                        "completeness": {
                            "type": "string",
                            "enum": ["Complete", "Incomplete", "Unknown"],
                        },
                        "owningShardIndex": {"type": "integer"},
                        "dependenciesSatisfied": {"type": "boolean"},
                        "findingCount": {"type": "integer"},
                        "actionableFindingCount": {"type": "integer"},
                    },
                },
            },
            "merge": {"type": "object", "x-kubernetes-preserve-unknown-fields": True},
            "findings": {"type": "object", "x-kubernetes-preserve-unknown-fields": True},
            "shardPods": {
                "type": "array",
                "items": {"type": "object", "x-kubernetes-preserve-unknown-fields": True},
            },
        },
    }

    crd = {
        "apiVersion": "apiextensions.k8s.io/v1",
        "kind": "CustomResourceDefinition",
        "metadata": {
            "name": f"{SCAN_PLURAL}.{GROUP}",
            "annotations": _annotations(translation.source_digest),
        },
        "spec": {
            "group": GROUP,
            "scope": "Namespaced",
            "names": {
                "kind": SCAN_KIND,
                "listKind": f"{SCAN_KIND}List",
                "plural": SCAN_PLURAL,
                "singular": SCAN_SINGULAR,
                "shortNames": ["ashscan"],
            },
            "versions": [
                {
                    "name": VERSION,
                    "served": True,
                    "storage": True,
                    "subresources": {"status": {}},
                    "additionalPrinterColumns": [
                        {"name": "Phase", "type": "string", "jsonPath": ".status.phase"},
                        {"name": "Shards", "type": "integer", "jsonPath": ".status.shardCount"},
                        {
                            "name": "Actionable",
                            "type": "integer",
                            "jsonPath": ".status.findings.actionable",
                        },
                        {
                            "name": "Coverage",
                            "type": "boolean",
                            "jsonPath": ".status.coverageComplete",
                        },
                        {
                            "name": "Incomplete",
                            "type": "string",
                            "jsonPath": ".status.incompleteScanners",
                        },
                        {"name": "Age", "type": "date", "jsonPath": ".metadata.creationTimestamp"},
                    ],
                    "schema": {
                        "openAPIV3Schema": {
                            "type": "object",
                            "properties": {"spec": spec, "status": status},
                            "required": ["spec"],
                        }
                    },
                }
            ],
        },
    }
    return crd, translation.as_report()


def build_mcp_crd() -> dict[str, Any]:
    config_schema, translation = build_config_schema()
    spec = {
        "type": "object",
        "required": ["image"],
        "properties": {
            "image": {"type": "string", "minLength": 1},
            "imagePullPolicy": {
                "type": "string",
                "enum": ["Always", "IfNotPresent", "Never"],
            },
            "replicas": {"type": "integer", "minimum": 1},
            "transport": {
                "type": "string",
                "enum": ["streamable-http", "sse"],
                "description": (
                    "stdio is not offered: there is no socket for a Service to route "
                    "to, so an AshMcpServer on stdio would be a pod nothing can reach."
                ),
            },
            "port": {"type": "integer", "minimum": 1, "maximum": 65535},
            "mountPath": {"type": "string", "pattern": "^/"},
            "statelessHttp": {
                "type": "boolean",
                "description": (
                    "Handle each streamable-HTTP request independently. Required "
                    "behind anything that may route consecutive requests to "
                    "different replicas, so effectively required whenever replicas > "
                    "1. An init container refuses to start -- exit 65 -- if this is "
                    "set and the image's ash mcp has no --stateless-http, because "
                    "without the flag the server runs stateful, answers 404 to every "
                    "injected session id, and still passes its health check."
                ),
            },
            "allowedHosts": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Host header values to accept. Lower-cased by the operator: a "
                    "load balancer lower-cases Host while the MCP SDK matches it "
                    "case-sensitively, so a mixed-case value yields 421 on every "
                    "request."
                ),
            },
            "auth": {
                "type": "object",
                "description": (
                    "Single-tenant header auth. The expected value is read from a "
                    "Secret, never inline: an inline value appears in `kubectl "
                    "describe pod` and in every audit record of the pod spec."
                ),
                "properties": {
                    "headerName": {"type": "string"},
                    "valueFrom": {
                        "type": "object",
                        "properties": {
                            "secretKeyRef": {
                                "type": "object",
                                "properties": {
                                    "name": {"type": "string"},
                                    "key": {"type": "string"},
                                    "optional": {"type": "boolean"},
                                },
                                "required": ["name", "key"],
                            }
                        },
                        "required": ["secretKeyRef"],
                    },
                },
                "required": ["headerName", "valueFrom"],
            },
            "serviceAccountName": {
                "type": "string",
                "description": (
                    "ServiceAccount for the MCP server pod. Defaults to ash-scan, which "
                    "manifests/rbac.yaml creates with no rules. Its token is never "
                    "mounted (automountServiceAccountToken: false)."
                ),
            },
            "runAsUser": {"type": "integer", "minimum": 1},
            "resources": _resources_schema("Resources for the MCP server pod."),
            "config": config_schema,
        },
    }
    return {
        "apiVersion": "apiextensions.k8s.io/v1",
        "kind": "CustomResourceDefinition",
        "metadata": {
            "name": f"{MCP_PLURAL}.{GROUP}",
            "annotations": _annotations(translation.source_digest),
        },
        "spec": {
            "group": GROUP,
            "scope": "Namespaced",
            "names": {
                "kind": MCP_KIND,
                "listKind": f"{MCP_KIND}List",
                "plural": MCP_PLURAL,
                "singular": MCP_SINGULAR,
                "shortNames": ["ashmcp"],
            },
            "versions": [
                {
                    "name": VERSION,
                    "served": True,
                    "storage": True,
                    "subresources": {"status": {}},
                    "additionalPrinterColumns": [
                        {"name": "Phase", "type": "string", "jsonPath": ".status.phase"},
                        {
                            "name": "Endpoint",
                            "type": "string",
                            "jsonPath": ".status.endpoint",
                        },
                        {"name": "Age", "type": "date", "jsonPath": ".metadata.creationTimestamp"},
                    ],
                    "schema": {
                        "openAPIV3Schema": {
                            "type": "object",
                            "properties": {
                                "spec": spec,
                                "status": {
                                    "type": "object",
                                    "x-kubernetes-preserve-unknown-fields": True,
                                },
                            },
                            "required": ["spec"],
                        }
                    },
                }
            ],
        },
    }


def render(obj: dict[str, Any]) -> str:
    header = (
        "# GENERATED FILE -- do not edit.\n"
        "# Regenerate with:\n"
        "#   python -m ash_operator.generate_manifests\n"
        "# spec.config is derived from AshConfig.model_json_schema(); see\n"
        "# ash_operator/crd_schema.py for what the translation had to drop, and\n"
        f"# generated/{TRANSLATION_REPORT} for the measured list.\n"
    )
    return header + yaml.safe_dump(obj, sort_keys=False, default_flow_style=False, width=100)


def render_all() -> dict[str, str]:
    """Return ``filename -> exact content``, touching no disk.

    The single source of what the generator emits. ``write_all`` and ``check`` both
    consume this, so the bytes a check compares against are the bytes a write would
    produce -- by construction rather than by two code paths agreeing.
    """
    scan_crd, translation = build_scan_crd()
    return {
        f"crd-{SCAN_PLURAL}.yaml": render(scan_crd),
        f"crd-{MCP_PLURAL}.yaml": render(build_mcp_crd()),
        TRANSLATION_REPORT: json.dumps(translation, indent=2, sort_keys=True) + "\n",
    }


def generated_on_disk(directory: Path) -> list[Path]:
    """Every file in *directory* the generator owns, by filename.

    Ownership is by pattern, not by a manifest file, so an orphan left behind by a
    removed kind is still recognised as ours and reported rather than ignored. A
    README or a kustomization alongside the generated files is not matched and
    survives.
    """
    owned = set(directory.glob(GENERATED_GLOB))
    report = directory / TRANSLATION_REPORT
    if report.is_file():
        owned.add(report)
    return sorted(owned)


def write_all(directory: Path) -> list[Path]:
    expected = render_all()
    directory.mkdir(parents=True, exist_ok=True)
    # Remove files we own that we no longer emit, so a CRD whose kind was removed does
    # not linger. Only files matching the generated pattern are touched.
    for stale in generated_on_disk(directory):
        if stale.name not in expected:
            stale.unlink()
    for name, text in sorted(expected.items()):
        (directory / name).write_text(text, encoding="utf-8")
    return [directory / name for name in sorted(expected)]


def _first_difference(want: bytes, got: bytes) -> str:
    """Describe where two byte strings diverge, for a message someone can act on."""
    limit = min(len(want), len(got))
    for offset in range(limit):
        if want[offset] != got[offset]:
            line = want[:offset].count(b"\n") + 1
            return (
                f"first differs at byte {offset} (line {line}): "
                f"expected {want[offset : offset + 1]!r}, found {got[offset : offset + 1]!r}"
            )
    return (
        f"identical for {limit} bytes, then lengths differ: expected {len(want)}, found {len(got)}"
    )


def check(directory: Path) -> int:
    """Compare the on-disk generated files against what the generator emits.

    Writes nothing. See the module docstring for why this does not ask git: git
    answers about tracking state, and a gate built on it passed having compared
    nothing whenever the directory was ignored, while failing on untracked files whose
    content matched exactly.
    """
    expected = render_all()
    if not expected:
        print(
            "::error::the generator emitted no files, so this gate compared nothing "
            "and must not report success.",
            file=sys.stderr,
        )
        return 1

    actual: dict[str, bytes] = {}
    for path in generated_on_disk(directory):
        try:
            actual[path.name] = path.read_bytes()
        except OSError as err:
            print(f"::error::could not read {path}: {err}", file=sys.stderr)
            return 1

    problems: list[str] = []
    for name, text in sorted(expected.items()):
        want = text.encode("utf-8")
        if name not in actual:
            problems.append(
                f"{name}: missing. The generator emits it and it is not in "
                f"{directory}. On a clean checkout this means it was generated but "
                f"never committed."
            )
        elif actual[name] != want:
            problems.append(f"{name}: differs. {_first_difference(want, actual[name])}")
    for name in sorted(set(actual) - set(expected)):
        problems.append(
            f"{name}: orphan. It matches the generated filename pattern but the "
            f"generator no longer emits it -- most likely a kind that was removed."
        )

    if problems:
        print(
            "::error::the committed manifests do not match what the generator emits. "
            "Run `python -m ash_operator.generate_manifests` and commit the result.",
            file=sys.stderr,
        )
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1

    total = sum(len(text.encode("utf-8")) for text in expected.values())
    print(
        f"{len(expected)} generated file(s), {total} bytes, match byte for byte. "
        f"Compared in memory; nothing was written and git was not consulted."
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="regenerate and fail if the committed copies differ",
    )
    parser.add_argument("--out", default=str(GENERATED_DIR))
    args = parser.parse_args(argv)
    directory = Path(args.out)
    if args.check:
        return check(directory)
    for path in write_all(directory):
        print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
