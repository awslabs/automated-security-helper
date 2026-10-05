"""Pins the operator's grants and the scanned-source schema at their current width.

Both are reviewed once and then only re-read by accident. Adding `secrets` to the
pods rule in rbac.yaml, or `hostPath` to the source schema, left every other unit
test green: crd-drift would notice the schema change, but regenerating the CRDs
clears that, and nothing read rbac.yaml for its verbs at all. A widening has to
change this file as well, which makes it a decision in the diff rather than a side
effect.

Two layers, because they fail for different reasons. EXPECTED_RULES and
EXPECTED_BINDINGS are an exact pin: every (apiGroups, resources, verbs) rule, and
every binding, as reviewed, read from every object `kubectl apply -f manifests/`
would send (.yaml, .yml and .json files, List items expanded) rather than rbac.yaml
alone, and manifests/ may hold only the reviewed files. Any change at all, `create`
on pods included, goes red there and has to be re-pinned by hand. The denylist
tests below it name the grants that must never be re-pinned, so the reviewer
updating the pin is told which kind of widening they are looking at.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
import yaml

from ash_operator.generate_manifests import _source_volume_schema

OPERATOR_DIR = Path(__file__).resolve().parents[1]
MANIFESTS_DIR = OPERATOR_DIR / "manifests"
RBAC_YAML = MANIFESTS_DIR / "rbac.yaml"
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
RBAC_KINDS = frozenset({"Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"})

# `kubectl apply -f manifests/` reads every file in the directory (not its
# subdirectories) whose name ends in one of these, so all of them are manifests.
KUBECTL_SUFFIXES = (".json", ".yaml", ".yml")
# Everything manifests/ may hold, as reviewed. A new file is a new set of objects
# the adopter applies, so adding one changes this set in the same diff.
EXPECTED_MANIFEST_FILES = frozenset({"operator.yaml", "rbac.yaml"})


def _json_documents(text: str) -> list:
    # kubectl decodes a .json file as a stream, so it may hold several objects back
    # to back. json.loads would reject that and hide every object after the first.
    decoder = json.JSONDecoder()
    docs = []
    rest = text.lstrip()
    while rest:
        doc, end = decoder.raw_decode(rest)
        docs.append(doc)
        rest = rest[end:].lstrip()
    return docs


def _flatten(doc: dict, path: Path) -> list[dict]:
    # kubectl expands a List (kind List, or any <Kind>List) client-side and applies
    # each item, so a ClusterRoleBinding inside one grants as much as a top-level one.
    assert isinstance(doc, dict), f"{path.name}: a document is not a mapping: {doc!r}"
    if str(doc.get("kind", "")).endswith("List") or "items" in doc:
        return [item for child in doc.get("items") or [] for item in _flatten(child, path)]
    return [doc]


def manifest_documents(manifests_dir: Path = MANIFESTS_DIR) -> list[tuple[Path, dict]]:
    # Every object `kubectl apply -f manifests/` would send, not only rbac.yaml's.
    # Adopters and the e2e apply the whole directory, so a ClusterRoleBinding in
    # operator.yaml, in a .yml or .json file, or wrapped in a List grants exactly as
    # much as one in rbac.yaml and has to be caught by the same pin.
    paths = sorted(
        path
        for path in manifests_dir.iterdir()
        if path.is_file() and path.suffix in KUBECTL_SUFFIXES
    )
    assert manifests_dir / "rbac.yaml" in paths, f"{manifests_dir / 'rbac.yaml'} is missing"
    docs = []
    for path in paths:
        text = path.read_text()
        raw = _json_documents(text) if path.suffix == ".json" else list(yaml.safe_load_all(text))
        docs.extend((path, obj) for doc in raw if doc for obj in _flatten(doc, path))
    assert docs, "manifests/ yielded no documents"
    return docs


def rbac_documents(manifests_dir: Path = MANIFESTS_DIR) -> list[dict]:
    return [doc for _, doc in manifest_documents(manifests_dir)]


def _as_rule(rule: dict) -> Rule:
    return tuple(tuple(sorted(rule.get(key) or [])) for key in ("apiGroups", "resources", "verbs"))


def rbac_rules() -> list[tuple[str, dict]]:
    rules = [
        (f"{doc['kind']}/{doc['metadata']['name']}", rule)
        for doc in rbac_documents()
        if doc["kind"] in ("Role", "ClusterRole")
        for rule in doc.get("rules") or []
    ]
    assert rules, "manifests/ yielded no rules, so the checks below would pass vacuously"
    return rules


def test_rbac_objects_live_only_in_rbac_yaml():
    # The pin below reads every manifest, so this is not what catches a widening. It
    # keeps the grants in the one file whose comments give the reason for each, so a
    # reviewer reading rbac.yaml is reading all of them.
    stray = [
        f"{path.name}: {doc['kind']}/{doc['metadata'].get('name')}"
        for path, doc in manifest_documents()
        if doc.get("kind") in RBAC_KINDS and path != RBAC_YAML
    ]
    assert not stray, f"RBAC objects outside rbac.yaml: {stray}"


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
        "The manifests' grants differ from the reviewed pin. If the change is intended, "
        "update EXPECTED_RULES in the same commit and say why in rbac.yaml."
    )


def actual_bindings(docs: list[dict]) -> set:
    actual = set()
    for doc in docs:
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
    return actual


def test_every_binding_is_exactly_the_reviewed_binding():
    assert actual_bindings(rbac_documents()) == EXPECTED_BINDINGS


def test_manifests_dir_holds_only_the_reviewed_files():
    # Hidden files and subdirectories too: neither is applied today, but a file a
    # reviewer did not expect is the place a grant would hide.
    present = {path.name for path in MANIFESTS_DIR.iterdir()}
    assert present == EXPECTED_MANIFEST_FILES, (
        f"manifests/ holds {sorted(present - EXPECTED_MANIFEST_FILES)} unreviewed and "
        f"lacks {sorted(EXPECTED_MANIFEST_FILES - present)}"
    )


ADMIN_BINDING = {
    "apiVersion": "rbac.authorization.k8s.io/v1",
    "kind": "ClusterRoleBinding",
    "metadata": {"name": "ash-operator-admin"},
    "roleRef": {
        "apiGroup": "rbac.authorization.k8s.io",
        "kind": "ClusterRole",
        "name": "cluster-admin",
    },
    "subjects": [{"kind": "ServiceAccount", "name": "ash-operator", "namespace": "ash-system"}],
}
ADMIN_ENTRY = (
    "ClusterRoleBinding/ash-operator-admin",
    None,
    "ClusterRole/cluster-admin",
    (("ServiceAccount", "ash-operator", "ash-system"),),
)


def _write_admin_yml(d: Path) -> None:
    (d / "extra.yml").write_text(yaml.safe_dump(ADMIN_BINDING))


def _write_admin_json(d: Path) -> None:
    # Two objects back to back, the binding second, as kubectl's stream decoder allows.
    namespace = {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "x"}}
    (d / "extra.json").write_text(json.dumps(namespace) + "\n" + json.dumps(ADMIN_BINDING))


def _append_admin_list(d: Path) -> None:
    wrapped = {"apiVersion": "v1", "kind": "List", "items": [ADMIN_BINDING]}
    with (d / "operator.yaml").open("a") as handle:
        handle.write("---\n" + yaml.safe_dump(wrapped))


def _append_admin_typed_list(d: Path) -> None:
    wrapped = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBindingList",
        "items": [{"apiVersion": "v1", "kind": "List", "items": [ADMIN_BINDING]}],
    }
    with (d / "operator.yaml").open("a") as handle:
        handle.write("---\n" + yaml.safe_dump(wrapped))


@pytest.mark.parametrize(
    "inject",
    [_write_admin_yml, _write_admin_json, _append_admin_list, _append_admin_typed_list],
    ids=["yml-file", "json-stream", "list-in-operator-yaml", "nested-typed-list"],
)
def test_the_pin_sees_a_binding_however_kubectl_would_read_it(tmp_path, inject):
    # Each of these is a cluster-admin grant that `kubectl apply -f manifests/` would
    # make and that an earlier version of manifest_documents did not read.
    shutil.copytree(MANIFESTS_DIR, tmp_path / "manifests")
    inject(tmp_path / "manifests")
    assert actual_bindings(rbac_documents(tmp_path / "manifests")) == EXPECTED_BINDINGS | {
        ADMIN_ENTRY
    }


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
