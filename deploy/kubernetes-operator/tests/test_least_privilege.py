"""Pins the operator's grants and the scanned-source schema at their current width.

Both are reviewed once and then only re-read by accident. Adding `secrets` to the
pods rule in rbac.yaml, or `hostPath` to the source schema, left every other unit
test green: crd-drift would notice the schema change, but regenerating the CRDs
clears that, and nothing read rbac.yaml for its verbs at all. A widening has to
change this file as well, which makes it a decision in the diff rather than a side
effect.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from ash_operator.generate_manifests import _source_volume_schema

OPERATOR_DIR = Path(__file__).resolve().parents[1]
RBAC_YAML = OPERATOR_DIR / "manifests" / "rbac.yaml"
SCAN_CRD = OPERATOR_DIR / "generated" / "crd-ashscans.yaml"

# Resources whose read or write turns the operator's account into something wider
# than a scan dispatcher: credential reads, a shell or a log stream into pods that
# hold scanned source, token minting, and anything that edits RBAC itself.
FORBIDDEN_RESOURCES = frozenset(
    {
        "secrets",
        "pods/exec",
        "pods/log",
        "pods/attach",
        "pods/portforward",
        "serviceaccounts/token",
        "roles",
        "rolebindings",
        "clusterroles",
        "clusterrolebindings",
    }
)
# Verbs that let an account grant or assume permissions it does not hold.
FORBIDDEN_VERBS = frozenset({"escalate", "bind", "impersonate"})

SOURCE_VOLUME_KEYS = {"persistentVolumeClaim", "configMap", "secret", "csi"}


def rbac_rules() -> list[tuple[str, dict]]:
    rules = [
        (f"{doc['kind']}/{doc['metadata']['name']}", rule)
        for doc in yaml.safe_load_all(RBAC_YAML.read_text())
        if doc and doc["kind"] in ("Role", "ClusterRole")
        for rule in doc.get("rules") or []
    ]
    assert rules, "rbac.yaml yielded no rules, so the checks below would pass vacuously"
    return rules


@pytest.mark.parametrize("field", ["apiGroups", "resources", "verbs", "resourceNames"])
def test_no_wildcard_anywhere(field):
    for owner, rule in rbac_rules():
        assert "*" not in (rule.get(field) or []), f"{owner} has '*' in {field}: {rule}"


def test_no_non_resource_urls():
    for owner, rule in rbac_rules():
        assert "nonResourceURLs" not in rule, f"{owner} grants nonResourceURLs: {rule}"


def test_no_forbidden_resource_is_granted():
    for owner, rule in rbac_rules():
        hit = FORBIDDEN_RESOURCES & set(rule.get("resources") or [])
        assert not hit, f"{owner} grants {sorted(hit)}: {rule}"


def test_no_rbac_api_group_at_all():
    for owner, rule in rbac_rules():
        assert "rbac.authorization.k8s.io" not in (rule.get("apiGroups") or []), (
            f"{owner} has a rule on the RBAC API group: {rule}"
        )


def test_no_privilege_granting_verb():
    for owner, rule in rbac_rules():
        hit = FORBIDDEN_VERBS & set(rule.get("verbs") or [])
        assert not hit, f"{owner} grants {sorted(hit)}: {rule}"


def test_the_source_schema_offers_exactly_the_reviewed_volume_types():
    # hostPath would hand the node's filesystem to a pod running third-party
    # scanners over foreign code; emptyDir describes a tree nothing populated,
    # which scans clean. Neither is offered, and nothing new is either.
    schema = _source_volume_schema()
    assert set(schema["properties"]) == SOURCE_VOLUME_KEYS
    # A structural schema prunes unknown members only when this is absent.
    assert not schema.get("x-kubernetes-preserve-unknown-fields")


def test_the_committed_crd_carries_the_same_source_schema():
    crd = yaml.safe_load(SCAN_CRD.read_text())
    (version,) = crd["spec"]["versions"]
    source = version["schema"]["openAPIV3Schema"]["properties"]["spec"]["properties"]["source"]
    assert set(source["properties"]) == SOURCE_VOLUME_KEYS
    assert not source.get("x-kubernetes-preserve-unknown-fields")
