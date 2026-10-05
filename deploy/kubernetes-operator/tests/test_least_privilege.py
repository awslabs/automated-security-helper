"""Pins the operator's grants and the scanned-source schema at their current width.

Both are reviewed once and then only re-read by accident. Adding `secrets` to the
pods rule in rbac.yaml, or `hostPath` to the source schema, left every other unit
test green: crd-drift would notice the schema change, but regenerating the CRDs
clears that, and nothing read rbac.yaml for its verbs at all. A widening has to
change this file as well, which makes it a decision in the diff rather than a side
effect.

Two layers, because they fail for different reasons. EXPECTED_RULES and
EXPECTED_BINDINGS are an exact pin: every (apiGroups, resources, verbs) rule, and
every binding, as reviewed. Any change at all, `create` on pods included, goes red
there and has to be re-pinned by hand. The denylist tests below it name the grants
that must never be re-pinned, so the reviewer updating the pin is told which kind of
widening they are looking at.
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


# The reviewed grants, rule for rule. Each rule is (apiGroups, resources, verbs) with
# every list sorted, so reordering a list in the YAML is not a change but adding or
# removing any member is. Keep this in step with the comments in rbac.yaml, which
# give the reason for each grant.
Rule = tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]

EXPECTED_RULES: dict[str, list[Rule]] = {
    "ClusterRole/ash-operator-crd-reader": [
        (("apiextensions.k8s.io",), ("customresourcedefinitions",), ("get", "list", "watch")),
    ],
    "Role/ash-operator": [
        (
            ("ash.awslabs.github.io",),
            ("ashmcpservers", "ashscans"),
            ("get", "list", "patch", "watch"),
        ),
        (("ash.awslabs.github.io",), ("ashmcpservers/status", "ashscans/status"), ("get", "patch")),
        (("batch",), ("jobs",), ("create", "delete", "get", "list", "watch")),
        (("",), ("pods",), ("get", "list", "watch")),
        (("",), ("configmaps",), ("create", "delete", "get", "list", "watch")),
        (("",), ("persistentvolumeclaims",), ("create", "delete", "get", "list", "watch")),
        (("",), ("events",), ("create",)),
        (("events.k8s.io",), ("events",), ("create",)),
        (("apps",), ("deployments",), ("create", "get", "list", "patch", "watch")),
        (("",), ("services",), ("create", "get", "list", "patch", "watch")),
    ],
}

# A binding widens an account without touching any rule above: binding the
# operator's account to a built-in ClusterRole such as `edit` would leave every rule
# pinned and every denylist test green. So the bindings are pinned too, as
# (kind/name, namespace, roleRef kind/name, sorted subjects).
EXPECTED_BINDINGS = {
    (
        "ClusterRoleBinding/ash-operator-crd-reader",
        None,
        "ClusterRole/ash-operator-crd-reader",
        (("ServiceAccount", "ash-operator", "ash-system"),),
    ),
    (
        "RoleBinding/ash-operator",
        "ash-system",
        "Role/ash-operator",
        (("ServiceAccount", "ash-operator", "ash-system"),),
    ),
}

RULE_KEYS = {"apiGroups", "resources", "verbs"}


def rbac_documents() -> list[dict]:
    docs = [doc for doc in yaml.safe_load_all(RBAC_YAML.read_text()) if doc]
    assert docs, "rbac.yaml yielded no documents"
    return docs


def _as_rule(rule: dict) -> Rule:
    return tuple(tuple(sorted(rule.get(key) or [])) for key in ("apiGroups", "resources", "verbs"))


def rbac_rules() -> list[tuple[str, dict]]:
    rules = [
        (f"{doc['kind']}/{doc['metadata']['name']}", rule)
        for doc in yaml.safe_load_all(RBAC_YAML.read_text())
        if doc and doc["kind"] in ("Role", "ClusterRole")
        for rule in doc.get("rules") or []
    ]
    assert rules, "rbac.yaml yielded no rules, so the checks below would pass vacuously"
    return rules


def test_every_rule_is_exactly_the_reviewed_rule():
    actual: dict[str, list[Rule]] = {}
    for doc in rbac_documents():
        if doc["kind"] not in ("Role", "ClusterRole"):
            continue
        owner = f"{doc['kind']}/{doc['metadata']['name']}"
        for rule in doc.get("rules") or []:
            # Only the three pinned keys. resourceNames or nonResourceURLs would change
            # what the rule means without changing the tuple compared below.
            assert set(rule) == RULE_KEYS, f"{owner} has a rule with keys {sorted(rule)}: {rule}"
        actual[owner] = sorted(_as_rule(rule) for rule in doc.get("rules") or [])
    expected = {owner: sorted(rules) for owner, rules in EXPECTED_RULES.items()}
    assert actual == expected, (
        "rbac.yaml's grants differ from the reviewed pin. If the change is intended, "
        "update EXPECTED_RULES in the same commit and say why in rbac.yaml."
    )


def test_every_binding_is_exactly_the_reviewed_binding():
    actual = set()
    for doc in rbac_documents():
        if doc["kind"] not in ("RoleBinding", "ClusterRoleBinding"):
            continue
        ref = doc["roleRef"]
        subjects = tuple(
            sorted(
                (subject["kind"], subject["name"], subject.get("namespace"))
                for subject in doc.get("subjects") or []
            )
        )
        actual.add(
            (
                f"{doc['kind']}/{doc['metadata']['name']}",
                doc["metadata"].get("namespace"),
                f"{ref['kind']}/{ref['name']}",
                subjects,
            )
        )
    assert actual == EXPECTED_BINDINGS


def test_the_scan_account_has_no_binding():
    # ash-scan runs third-party scanners over foreign source. It exists so those pods
    # do not run as `default`, and holds no grant at all.
    for doc in rbac_documents():
        for subject in doc.get("subjects") or []:
            assert subject.get("name") != "ash-scan", f"{doc['kind']} binds ash-scan: {doc}"


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
